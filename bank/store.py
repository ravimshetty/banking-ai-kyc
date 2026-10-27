"""Core banking system (CBS) facade over PostgreSQL. Agents only touch data through these methods,
so pointing at a real CBS later means changing these bodies, not the agents.

All SQL uses bound parameters (%s), never string formatting, so nothing a user types can alter a query."""
from __future__ import annotations

import pandas as pd

from bank.db import Database

TXN_COLS = ("txn_id, customer_id, ts, amount, direction, channel, merchant_category, country, "
            "new_device, counterparty, is_fraud")


class CoreBanking:
    def __init__(self, db: Database | None = None):
        self.db = db or Database()

    # ---------- reads ----------
    def customer(self, cid: str) -> dict:
        row = self.db.one("SELECT * FROM customers WHERE customer_id = %s", (cid,))
        if row is None:
            raise KeyError(f"Unknown customer {cid}")
        return row

    def customer_ids(self) -> list[str]:
        return [r["customer_id"] for r in self.db.all("SELECT customer_id FROM customers ORDER BY customer_id")]

    def account(self, cid: str) -> dict:
        row = self.db.one("SELECT * FROM accounts WHERE customer_id = %s", (cid,))
        if row is None:
            raise KeyError(f"No account for customer {cid}")
        return row

    def transactions(self, cid: str, limit: int | None = None, before=None) -> pd.DataFrame:
        """A customer's transactions, newest first (served by ix_txn_customer_ts)."""
        sql = f"SELECT {TXN_COLS} FROM transactions WHERE customer_id = %s"
        params: list = [cid]
        if before is not None:
            sql += " AND ts < %s"
            params.append(pd.Timestamp(before).to_pydatetime())
        sql += " ORDER BY ts DESC"
        if limit:
            sql += " LIMIT %s"
            params.append(int(limit))
        return self._txn_frame(self.db.df(sql, tuple(params)))

    def transaction(self, txn_id: str) -> dict:
        row = self.db.one(f"SELECT {TXN_COLS} FROM transactions WHERE txn_id = %s", (txn_id,))
        if row is None:
            raise KeyError(f"Unknown transaction {txn_id}")
        return row

    def sanctions(self) -> pd.DataFrame:
        return self.db.df("SELECT name, list FROM sanctions")

    # ---------- writes (only ever called after policy/approval checks) ----------
    def set_card_status(self, cid: str, status: str) -> dict:
        # ACTIVE -> TEMP_FROZEN (reversible) or BLOCKED (permanent, needs approval); CHECK constraint guards values
        row = self.db.execute("UPDATE accounts SET card_status = %s, updated_at = now() "
                              "WHERE customer_id = %s RETURNING *", (status, cid))
        if row is None:
            raise KeyError(f"No account for customer {cid}")
        return row

    def open_dispute(self, cid: str, txn_id: str, reason: str) -> dict:
        txn = self.transaction(txn_id)
        if txn["customer_id"] != cid:
            raise PermissionError("Transaction does not belong to this customer")
        # dispute_id comes from a sequence, so ids stay unique across processes and restarts
        return self.db.execute("INSERT INTO disputes (customer_id, txn_id, amount, reason) VALUES (%s, %s, %s, %s) "
                               "RETURNING dispute_id, customer_id, txn_id, amount, reason, status",
                               (cid, txn_id, txn["amount"], reason))

    # ---------- helpers ----------
    @staticmethod
    def _txn_frame(df: pd.DataFrame) -> pd.DataFrame:
        """Normalise dtypes so the agents and AML rules see the same frame shape."""
        if df.empty:
            return df
        df["ts"] = pd.to_datetime(df["ts"])
        df["amount"] = df["amount"].astype(float)
        df["new_device"] = df["new_device"].astype(bool)
        df["is_fraud"] = df["is_fraud"].astype(int)
        return df
