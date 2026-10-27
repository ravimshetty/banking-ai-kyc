"""Multi-agent orchestrator.

    user_id -> RBAC principal (roles + permissions from PostgreSQL) -> guardrails
            -> router (LLM offered only permitted intents) -> RBAC check on intent + target customer
            -> specialist agent -> tools -> (auto action | approval proposal) -> answer composer -> audit

Callers pass WHO they are (user_id), never what role they have: the role is looked up, not trusted.

Specialists: CustomerService (balances, transactions, cards, disputes, reported misuse, KYC status, policy Q&A)
and Compliance (KYC/AML reviews, sanctions screening, SAR drafts). Tools are deterministic; the LLM never
decides anything that touches money or a customer's status.
"""
from __future__ import annotations

import re

import pandas as pd

import config
from bank import aml
from bank.audit import ApprovalQueue, AuditLog
from bank.db import Database
from bank.guardrails import check_input, mask_pii
from bank.kb import PolicyKB
from bank.llm import LLM
from bank.rbac import RBAC, AccessDenied, Principal
from bank.store import CoreBanking


def _ids(text: str, pattern: str) -> list[str]:
    return re.findall(pattern, text)


def _fmt(x: float) -> str:
    return f"{config.CURRENCY} {x:,.2f}"


class Ctx:
    def __init__(self, principal: Principal, customer_id, message):
        self.principal, self.customer_id, self.message = principal, customer_id, message
        self.user_id = principal.user_id
        self.actions: list[dict] = []
        self.approvals: list[dict] = []
        self.sources: list[str] = []


class BankingAgents:
    def __init__(self, db: Database | None = None):
        self.db = db or Database()           # one PostgreSQL connection shared by every component
        self.cbs = CoreBanking(self.db)
        self.kb = PolicyKB()
        self.llm = LLM()
        self.audit = AuditLog(self.db)
        self.queue = ApprovalQueue(self.db, self.audit)
        self.rbac = RBAC(self.db)

    # ======================= entry point =======================
    def handle(self, message: str, user_id: str, customer_id: str | None = None) -> dict:
        # 1) Who is asking? Roles and permissions come from the database, never from the caller.
        try:
            p = self.rbac.load(user_id)
        except AccessDenied as e:
            return self._deny("login", user_id, e)

        # 2) Guardrails before anything reaches the router or the LLM
        ok, refusal = check_input(message)
        if not ok:
            self.audit.write("blocked_input", user=p.user_id, message=message)
            return {"intent": "blocked", "agent": "guardrails", "answer": refusal, "actions": [], "approvals": []}

        # 3) Which customer is this about? Explicit argument, else an id in the message, else the user's own.
        #    No special case for customers: naming someone else simply fails the scoped permission check.
        mentioned = _ids(message, r"\bC\d{4}\b")
        if p.is_customer:   # any other customer id they name becomes the target, and is then refused
            target = next((c for c in mentioned if c != p.customer_id), customer_id or p.customer_id)
        else:
            target = customer_id or (mentioned[0] if mentioned else None)

        # 4) Route among permitted intents only, then check the chosen intent against the target customer
        intent = self.llm.classify(message, self.rbac.allowed_intents(p))
        try:
            self.rbac.require_intent(p, intent, target)
        except AccessDenied as e:
            return self._deny(intent, p.user_id, e)

        ctx = Ctx(p, target, message)
        handler = {
            "balance": self._balance, "recent_transactions": self._recent, "policy_question": self._policy,
            "dispute": self._dispute, "freeze_card": self._freeze, "kyc_status": self._kyc_status,
            "report_fraud": self._report_fraud, "aml_review": self._aml_review,
            "smalltalk": self._smalltalk,
        }[intent]
        try:
            agent, facts, fallback = handler(ctx)
        except AccessDenied as e:
            return self._deny(intent, p.user_id, e)
        except (KeyError, PermissionError) as e:
            agent, facts, fallback = "router", {"error": str(e)}, f"I couldn't complete that: {e}"
        answer = mask_pii(self.llm.compose(message, facts, fallback))
        result = {"intent": intent, "agent": agent, "answer": answer, "data": facts,
                  "actions": ctx.actions, "approvals": ctx.approvals, "sources": ctx.sources}
        self.audit.write("request_handled", user=p.user_id, roles=sorted(p.roles), customer=target, intent=intent,
                         agent=agent, actions=ctx.actions, approvals=[a["approval_id"] for a in ctx.approvals])
        return result

    def _deny(self, intent: str, user_id: str | None, e: AccessDenied) -> dict:
        self.audit.write("access_denied", user=user_id, intent=intent, permission=e.permission, reason=e.reason)
        return {"intent": intent, "agent": "rbac", "answer": f"Access denied: {e.reason}", "actions": [],
                "approvals": []}

    # ======================= Customer service agent =======================
    def _balance(self, ctx):
        acct = self.cbs.account(ctx.customer_id)
        facts = {"balance": acct["balance"], "account_id": acct["account_id"], "card_status": acct["card_status"]}
        return "customer_service", facts, f"Your available balance in {acct['account_id']} is {_fmt(acct['balance'])}."

    def _recent(self, ctx):
        n = int((_ids(ctx.message, r"\blast (\d+)\b") or [5])[0])
        df = self.cbs.transactions(ctx.customer_id, limit=min(n, 20))
        rows = df[["txn_id", "ts", "direction", "amount", "merchant_category", "channel", "country"]]
        lines = [f"{r.ts:%d %b %H:%M}  {r.direction:<6} {_fmt(r.amount):>18}  {r.merchant_category} ({r.txn_id})"
                 for r in rows.itertuples()]
        return "customer_service", {"transactions": rows.to_dict("records")}, \
            "Your recent transactions:\n" + "\n".join(lines)

    def _policy(self, ctx):
        hits = self.kb.search(ctx.message)
        if not hits:
            return "customer_service", {"policy": []}, \
                "I couldn't find that in the bank's policies. I can connect you to a branch officer."
        ctx.sources = [f"{h['source']}#{h['section']}" for h in hits]
        top = hits[0]
        return "customer_service", {"policy": hits}, f"{top['text']}\n(source: {top['source']} — {top['section']})"

    def _dispute(self, ctx):
        txn_ids = _ids(ctx.message, r"\bT\d{7}\b")
        if not txn_ids:
            return "customer_service", {"need": "txn_id"}, \
                "Which transaction would you like to dispute? Please share its reference (e.g. T0001234)."
        d = self.cbs.open_dispute(ctx.customer_id, txn_ids[0], reason=ctx.message[:200])
        ctx.actions.append({"action": "OPEN_DISPUTE", **d})
        policy = self.kb.search("dispute resolution timelines shadow reversal", k=1)
        ctx.sources = [f"{p['source']}#{p['section']}" for p in policy]
        return "customer_service", {"dispute": d, "policy": policy}, \
            (f"Dispute {d['dispute_id']} opened for {txn_ids[0]} ({_fmt(d['amount'])}). "
             "A shadow reversal is credited within 10 working days; final resolution within 90 days.")

    def _freeze(self, ctx):
        acct = self.cbs.set_card_status(ctx.customer_id, "TEMP_FROZEN")
        ctx.actions.append({"action": "TEMP_FREEZE_CARD", "card_id": acct["card_id"], "by": "customer_request"})
        return "customer_service", {"card": acct}, \
            (f"Your card {acct['card_id']} is temporarily frozen. You can unfreeze it any time from the app. "
             "If it's lost or stolen, I can request a permanent block and replacement.")

    def _smalltalk(self, ctx):
        return "customer_service", {}, ("I can help with balances, transactions, card freezes, disputes, "
                                        "unauthorised transactions, your KYC status and bank policies.")

    def _misuse_signals(self, txn: dict) -> list[str]:
        """Plain-language red flags for the analyst who approves the permanent block (never shown to customers)."""
        history = self.cbs.transactions(txn["customer_id"])
        debits = history[(history.direction == "DEBIT") & (history.txn_id != txn["txn_id"])]
        signals = []
        typical = float(debits.amount.median()) if len(debits) else 0.0
        if typical and float(txn["amount"]) >= config.UNUSUAL_AMOUNT_MULTIPLE * typical:
            signals.append(f"amount is {float(txn['amount']) / typical:.0f}x the customer's typical spend")
        if txn["country"] != self.cbs.customer(txn["customer_id"])["home_country"]:
            signals.append(f"transaction in {txn['country']}, outside the home country")
        if txn["new_device"]:
            signals.append("made from a new device")
        if txn["ts"].hour in config.NIGHT_HOURS:
            signals.append(f"made at night ({txn['ts']:%H:%M})")
        return signals or ["no automatic red flags: rely on the customer's report"]

    def _report_fraud(self, ctx):
        """The customer says they didn't make a transaction: protect first, then let a human decide the rest."""
        txn_ids = _ids(ctx.message, r"\bT\d{7}\b")
        if not txn_ids:   # customer didn't give a reference: take their latest debit
            debits = self.cbs.transactions(ctx.customer_id)
            txn_ids = [debits[debits.direction == "DEBIT"].iloc[0].txn_id]
        txn_id = txn_ids[0]
        txn = self.cbs.transaction(txn_id)
        if txn["customer_id"] != ctx.customer_id:
            raise PermissionError("That transaction is not on your account")
        txn["ts"] = pd.Timestamp(txn["ts"])
        # 1) protect first: temporary freeze is reversible
        acct = self.cbs.set_card_status(ctx.customer_id, "TEMP_FROZEN")
        ctx.actions.append({"action": "TEMP_FREEZE_CARD", "card_id": acct["card_id"], "by": "customer_service_agent"})
        # 2) open a dispute so the zero-liability clock is recorded
        d = self.cbs.open_dispute(ctx.customer_id, txn_id, reason="customer reported unauthorised")
        ctx.actions.append({"action": "OPEN_DISPUTE", **d})
        # 3) permanent block is irreversible: a card-operations analyst decides
        ctx.approvals.append(self.queue.propose(
            "BLOCK_CARD_PERMANENT", {"customer_id": ctx.customer_id, "card_id": acct["card_id"], "txn_id": txn_id},
            proposed_by="customer_service_agent", requested_by=ctx.user_id,
            rationale="Customer-reported unauthorised transaction; " + "; ".join(self._misuse_signals(txn))))
        policy = self.kb.search("zero liability unauthorised electronic transaction reported", k=1)
        ctx.sources = [f"{p['source']}#{p['section']}" for p in policy]
        return "customer_service", {"dispute": d, "card_status": "TEMP_FROZEN", "policy": policy}, \
            (f"I've frozen your card {acct['card_id']} and opened dispute {d['dispute_id']} for {txn_id} "
             f"({_fmt(d['amount'])}). Because you reported it promptly, zero-liability protection applies. "
             "Our card team will review it and arrange a replacement card.")

    def _kyc_status(self, ctx):
        """KYC status. Customers see their status and what to submit; compliance staff also see the sanctions
        screening result. Customers and front-line staff never see screening or AML results (no tipping-off)."""
        cust = self.cbs.customer(ctx.customer_id)
        docs = self.kb.search("KYC documents proof of identity address", k=1)
        rekyc = self.kb.search("periodic re-KYC pending debit restrictions", k=1)
        ctx.sources = [f"{p['source']}#{p['section']}" for p in docs + rekyc]
        facts = {"customer_id": cust["customer_id"], "kyc_status": cust["kyc_status"], "policy": docs + rekyc}
        agent = "customer_service"
        if cust["kyc_status"] == "VERIFIED":
            text = "Your KYC is up to date (VERIFIED). No documents are needed right now."
        else:
            text = ("Your KYC needs to be renewed (re-KYC pending). Please submit a proof of identity and a proof "
                    "of address (passport, voter ID, driving licence or Aadhaar with consent); PAN is needed for "
                    "high-value transactions. Until re-KYC is complete, some debits may be restricted.")
        if not ctx.principal.is_customer:   # staff view, in the third person
            text = f"{cust['customer_id']} ({cust['name']}): KYC {cust['kyc_status']}."
            # Screening results only for compliance staff: front-line staff talk to customers (tipping-off risk)
            if self.rbac.can(ctx.principal, "aml.review"):
                hits = aml.screen_name(cust["name"], self.cbs.sanctions())
                facts["sanctions_hits"], agent = hits, "compliance"
                text += (f" Sanctions screening: possible match '{hits[0]['matched_name']}' "
                         f"(similarity {hits[0]['similarity']}) - run an AML review." if hits
                         else " Sanctions screening: no match.")
        return agent, facts, text

    # ======================= Compliance agent =======================
    def _aml_review(self, ctx):
        cust = self.cbs.customer(ctx.customer_id)
        r = aml.assess_customer(cust, self.cbs.transactions(ctx.customer_id), self.cbs.sanctions())
        if r["recommend_sar"]:
            ctx.approvals.append(self.queue.propose(
                "FILE_SAR", {"customer_id": ctx.customer_id, "alerts": [a["rule"] for a in r["alerts"]]},
                proposed_by="compliance_agent", requested_by=ctx.user_id,
                rationale="; ".join(a["detail"] for a in r["alerts"])))
        lines = [f"[{a['severity']}] {a['rule']}: {a['detail']}" for a in r["alerts"]] or ["no alerts"]
        return "compliance", {"aml": r}, \
            (f"AML review {ctx.customer_id}: risk {r['risk_score']}/100 ({r['risk_band']}).\n" + "\n".join(lines)
             + ("\nSAR draft queued for MLRO approval." if r["recommend_sar"] else ""))

    # ======================= approvals =======================
    def decide(self, approval_id: str, user_id: str, approve: bool, note: str = "") -> dict:
        """A human decides. RBAC (action right, not their own request) is checked under the row lock;
        the decision and its effect commit together or not at all."""
        p = self.rbac.load(user_id)
        try:
            with self.db.transaction():
                item = self.queue.decide(approval_id, p.user_id, approve, note,
                                         check=lambda it: self.rbac.require_approval(p, it))
                if approve:
                    self._apply(item, p.user_id)
        except AccessDenied as e:
            self.audit.write("access_denied", user=p.user_id, intent="approval", approval_id=approval_id,
                             permission=e.permission, reason=e.reason)
            raise
        return item

    def pending_for(self, user_id: str) -> list[dict]:
        """The approval inbox: only items this user is allowed to decide."""
        p = self.rbac.load(user_id)
        return [i for i in self.queue.pending() if self.rbac.can_decide(p, i)]

    def audit_events(self, user_id: str, limit: int = 50) -> list[dict]:
        self.rbac.require(self.rbac.load(user_id), "audit.read")
        return self.db.all("SELECT id, ts, event, details FROM audit_log ORDER BY id DESC LIMIT %s", (limit,))

    def _apply(self, item: dict, approver: str) -> None:
        """Carry out an approved action in the core banking system."""
        p = item["payload"]
        if item["action"] == "BLOCK_CARD_PERMANENT":
            self.cbs.set_card_status(p["customer_id"], "BLOCKED")
        elif item["action"] == "FILE_SAR":
            self.audit.write("sar_filed", customer=p["customer_id"], approver=approver)
