"""Append-only audit trail and human-in-the-loop approval queue, both persisted in PostgreSQL.

- audit_log rejects UPDATE/DELETE via a trigger (see db/schema.sql), so the trail can only grow.
- approvals survive restarts; decide() locks the row (SELECT ... FOR UPDATE) so two approvers
  can't both act on the same item, and the table's CHECK constraint enforces maker-checker as well."""
from __future__ import annotations

import json
import uuid

from bank.db import Database, Jsonb
from bank.guardrails import mask_pii


class AuditLog:
    def __init__(self, db: Database):
        self.db = db

    def write(self, event: str, **fields) -> dict:
        # Serialise, mask PII on the text, then store as JSONB: personal data never reaches the table
        details = json.loads(mask_pii(json.dumps(fields, default=str)))
        self.db.execute("INSERT INTO audit_log (event, details) VALUES (%s, %s)", (event, Jsonb(details)))
        return {"event": event, **details}

    def count(self) -> int:
        return self.db.one("SELECT count(*) AS n FROM audit_log")["n"]


class ApprovalQueue:
    """Actions an agent may propose but not execute: SAR filing and permanent card blocks."""

    COLS = "approval_id, action, payload, proposed_by, requested_by, rationale, status, approver, note"

    def __init__(self, db: Database, audit: AuditLog):
        self.db, self.audit = db, audit

    def propose(self, action: str, payload: dict, proposed_by: str, rationale: str, requested_by: str) -> dict:
        """proposed_by = the agent that drafted it; requested_by = the human whose request led to it."""
        item = self.db.execute(
            f"INSERT INTO approvals (approval_id, action, payload, proposed_by, requested_by, rationale) "
            f"VALUES (%s, %s, %s, %s, %s, %s) RETURNING {self.COLS}",
            (f"AP-{uuid.uuid4().hex[:8]}", action, Jsonb(payload), proposed_by, requested_by, rationale))
        self.audit.write("approval_proposed", **item)
        return item

    def pending(self) -> list[dict]:
        return self.db.all(f"SELECT {self.COLS} FROM approvals WHERE status = 'PENDING' ORDER BY created_at")

    def get(self, approval_id: str) -> dict:
        item = self.db.one(f"SELECT {self.COLS} FROM approvals WHERE approval_id = %s", (approval_id,))
        if item is None:
            raise KeyError(f"Unknown approval {approval_id}")
        return item

    def decide(self, approval_id: str, approver: str, approve: bool, note: str = "", check=None) -> dict:
        """`check(item)` raises if `approver` may not decide this item (RBAC); it runs under the row lock."""
        with self.db.transaction():
            item = self.db.one(f"SELECT {self.COLS} FROM approvals WHERE approval_id = %s FOR UPDATE",
                               (approval_id,))
            if item is None:
                raise KeyError(f"Unknown approval {approval_id}")
            if item["status"] != "PENDING":
                raise ValueError(f"{approval_id} already {item['status']}")
            if approver == item["proposed_by"]:
                raise PermissionError("Maker-checker: the proposer cannot approve their own action")
            if check:
                check(item)
            item = self.db.execute(
                f"UPDATE approvals SET status = %s, approver = %s, note = %s, decided_at = now() "
                f"WHERE approval_id = %s RETURNING {self.COLS}",
                ("APPROVED" if approve else "REJECTED", approver, note, approval_id))
            self.audit.write("approval_decided", **item)
        return item
