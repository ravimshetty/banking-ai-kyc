# Testing in VS Code: step by step

This project has two agents: **Customer Service** and **KYC/AML Compliance**. There are no models to train.

You can run it in two ways:
- **Docker (recommended on your laptop):** Python runs inside Linux, so Windows Smart App Control can't block anything. You only need Docker Desktop and VS Code.
- **Local Python:** a `.venv` on Windows. Use this only if Smart App Control is off.

Every step below shows what you should see.

---

## Part A: One-time setup

1. Install and start **Docker Desktop**, and wait until it shows "Engine running".
2. Unzip the project, e.g. to `D:\Gen_AI\banking_ai_kyc`, then in VS Code go to **File → Open Folder…** and pick it.
3. When VS Code suggests the recommended extensions, click **Install All**. The important ones are REST Client and Dev Containers.
4. In the VS Code terminal (**Terminal → New Terminal**), run:
   ```powershell
   Copy-Item .env.example .env
   docker rm -f banking-ai-postgres      # only if an old container with this name exists; an error here is fine
   docker compose --profile app build   # 2-3 minutes the first time
   ```
   The build ends with `banking-ai-app  Built`.

## Part B: Build the bank and run the demo

```powershell
docker compose run --rm app python data/generate.py
docker compose run --rm app python -m db.load
docker compose run --rm app python demo.py
```

| Command | You should see |
|---|---|
| `generate.py` | `customers=500 transactions=36322 pending_rekyc=125 sanctions=5` |
| `db.load` | `Loaded into PostgreSQL: customers=500, accounts=500, transactions=36322, sanctions=5, users=509` |
| `demo.py` | The scenarios below, ending with `Audit trail (read by auditor_01): 31 events, 9 access denials recorded` |

**Demo checklist**
- [ ] **Customer: balance**: `Your available balance in A00177 is INR 86,303.36.`
- [ ] **Policy question (RAG)**: the answer ends with `(source: accounts.md — Minimum balance)`
- [ ] **Customer reports fraud**:
  - `TEMP_FREEZE_CARD` and `OPEN_DISPUTE D0001`;
  - `BLOCK_CARD_PERMANENT (pending human)` with red flags: 9x typical spend, outside the home country.
- [ ] **Guardrails**: the injection and the OTP message both show `agent=guardrails`
- [ ] **KYC**:
  - the verified customer sees "up to date";
  - C0002 is told which documents to submit;
  - asking about someone else's KYC gives `Access denied`.
- [ ] **No tipping-off**:
  - the support agent sees `C0018 (Viktor Draganoff): KYC VERIFIED.` and nothing more;
  - the compliance officer also sees `possible match 'Viktor Draganov'`.
- [ ] **AML**:
  - C0006 shows `STRUCTURING` and C0018 shows `SANCTIONS_SCREENING`, each with a SAR draft;
  - C0100 shows `no alerts`.
- [ ] **Decisions**:
  - the customer, the support agent and the compliance officers are `DENIED`;
  - the analyst blocks the card;
  - the MLRO files one SAR and rejects the other as a false positive.
- [ ] **Access administration**: self-grant, segregation of duties and a non-admin grant are all `DENIED`; the revoke is `ALLOWED`

## Part C: Automated tests

```powershell
docker compose run --rm app python -m pytest -v
```
Expected: **28 passed**.

| Area | Tests |
|---|---|
| Guardrails | `test_pii_masking`, `test_injection_and_otp_blocked`, `test_sql_injection_in_message_is_inert` |
| Customer service | `test_policy_rag_returns_source`, `test_report_fraud_freezes_and_queues_permanent_block`, `test_analyst_approves_permanent_block`, `test_planted_misuse_gets_red_flags_for_the_analyst` |
| KYC | `test_customer_sees_own_kyc_status_and_documents`, `test_customer_cannot_see_another_customers_kyc`, `test_no_tipping_off_about_sanctions_screening` |
| AML | `test_aml_planted_patterns_detected`, `test_aml_false_positive_rate_low` |
| RBAC and scoping | `test_customer_cannot_access_other_customer`, `test_customer_cannot_run_staff_intents`, `test_scoped_permissions_own_vs_any`, `test_support_agent_cannot_investigate`, `test_router_only_offered_permitted_intents`, `test_unknown_and_deactivated_users_are_denied`, `test_back_office_functions_need_their_permission` |
| Human in the loop | `test_only_mlro_files_sar_and_not_their_own_request`, `test_inbox_shows_only_decidable_items`, `test_failed_decision_rolls_back` |
| Database guarantees | `test_segregation_of_duties_in_app_and_database`, `test_no_self_escalation`, `test_revoke_takes_effect_immediately_and_is_audited`, `test_audit_log_is_append_only_in_database`, `test_maker_checker_enforced_by_database_constraints`, `test_approvals_and_disputes_survive_restart` |

To run one group only, filter by name: `docker compose run --rm app python -m pytest -v -k kyc` (or `-k aml`, `-k rbac`).

**Prove a test really guards something:**
1. In `bank/agents.py`, inside `_kyc_status`, change `if self.rbac.can(ctx.principal, "aml.review"):` to `if True:`.
2. Run the tests. `test_no_tipping_off_about_sanctions_screening` fails, because support staff would now see the screening result.
3. Undo the change.

## Part D: Call the API one request at a time

1. Start the API and leave the terminal running:
   ```powershell
   docker compose run --rm app python -m db.load
   docker compose run --rm --service-ports app python -m uvicorn api:app --host 0.0.0.0 --port 8000
   ```
2. Browser: **http://127.0.0.1:8000/docs** (not 0.0.0.0) shows Swagger UI titled "Banking AI: Customer Service + KYC/AML".
3. In VS Code, open **`requests.http`** and click **Send Request** above each block, **top to bottom**. There are 32 steps in five parts, and each comment states the expected response:
   - **Part 1 (steps 1–12):** the customer: balance, transactions, RAG, KYC, reporting misuse, RBAC denials, guardrails.
   - **Part 2 (steps 13–16):** the permanent card block. The customer and support agent get 403; the analyst approves.
   - **Part 3 (steps 17–20):** staff views. Support doesn't see sanctions screening; compliance does.
   - **Part 4 (steps 21–27):** AML reviews. The compliance officer can't file a SAR (403). The MLRO files one and rejects the false positive.
   - **Part 5 (steps 28–32):** admin role matrix, segregation of duties (403), no self-escalation (403), the audit log, an unknown user (403).
4. Stop the API with **Ctrl+C**. To start over, run the `db.load` command again.

The same calls work in Swagger:
1. Expand an endpoint and click **Try it out**.
2. Fill in **x-user** and the body. In the `/chat` body, delete `customer_id` or set it to `null`.
3. Click **Execute**.

## Part E: Debug inside the container (Test Explorer and breakpoints)

1. Press **Ctrl+Shift+P** and choose **Dev Containers: Reopen in Container**. The first time takes about a minute.
2. Click the **beaker icon** to see 28 tests, then **Run Tests**.
3. Set breakpoints:
   - `bank/agents.py` → `handle()`: every request enters here;
   - `_kyc_status()`: the KYC answer and the tipping-off rule;
   - `_report_fraud()`: freeze, dispute and the approval proposal;
   - `bank/rbac.py` → `require_intent()`: the access decision.
4. In **Run and Debug** (Ctrl+Shift+D), pick **"3. Demo"** or **"4. API server (debug)"** and press **F5**. **F10** steps over a line, **F11** steps into a call, and the Variables panel shows `principal`, `intent` and `facts`.
5. To go back to Windows, choose **Dev Containers: Reopen Folder Locally**.

## Part F: Look inside PostgreSQL

```powershell
docker compose exec postgres psql -U bank -d banking_ai
```
```sql
\dt                                                                   -- 13 tables
SELECT kyc_status, count(*) FROM customers GROUP BY 1;                -- 375 VERIFIED, 125 PENDING_REKYC
SELECT approval_id, action, status, requested_by, approver FROM approvals ORDER BY created_at;
SELECT id, event, details->>'user' AS who FROM audit_log ORDER BY id DESC LIMIT 15;
DELETE FROM audit_log;                                                -- ERROR: append-only
\q
```

## Optional: use a real LLM

1. Set `OPENAI_API_KEY=sk-...` in `.env`.
2. Rebuild with `docker compose --profile app build`, or just rerun; `.env` is read at start.

With a key, the LLM routes intents and phrases answers, but facts and decisions still come from the tools. The tests always run offline.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `no such service: app` / `No services to build` | You still have the old `docker-compose.yml`; copy the one from this zip |
| `container name "/banking-ai-postgres" is already in use` | `docker rm -f banking-ai-postgres` |
| Browser says `ERR_ADDRESS_INVALID` for 0.0.0.0 | Use http://127.0.0.1:8000/docs |
| Inside Docker: `connection refused` to `localhost:5432` | In `.env`, comment out the `DATABASE_URL=` line |
| `DLL load failed … Application Control policy` (local Python) | Smart App Control: use the Docker commands instead |
| Start completely fresh | `docker compose down -v`, then Part A step 4 and Part B |
