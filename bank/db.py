"""PostgreSQL access layer (psycopg 3). The only module that talks to the driver.

Every other module goes through `Database`, so swapping drivers, adding a pool or pointing at a
managed service (RDS, Cloud SQL, Azure) is a change here and in DATABASE_URL only.
"""
from __future__ import annotations

import csv
from decimal import Decimal
from contextlib import contextmanager
from pathlib import Path

import pandas as pd
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

import config

__all__ = ["Database", "DatabaseError", "Jsonb"]

DatabaseError = psycopg.Error   # driver-neutral name for callers that need to catch database errors


class Database:
    def __init__(self, url: str = config.DATABASE_URL):
        self.url = url
        # autocommit: each statement is its own transaction unless wrapped in `transaction()`
        self.conn = psycopg.connect(url, autocommit=True, row_factory=dict_row)

    # ---------------------------------------------------------------- reads
    def df(self, sql: str, params: tuple | dict | None = None) -> pd.DataFrame:
        """Run a query and return a DataFrame (NUMERIC -> float, so models and pandas math just work)."""
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
            cols = [c.name for c in cur.description]
        df = pd.DataFrame(rows, columns=cols)
        for c in df.columns:
            if df[c].dtype == object and df[c].map(lambda v: isinstance(v, Decimal)).any():
                df[c] = df[c].astype(float)
        return df

    def one(self, sql: str, params: tuple | dict | None = None) -> dict | None:
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
        return _floats(row) if row else None

    def all(self, sql: str, params: tuple | dict | None = None) -> list[dict]:
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            return [_floats(r) for r in cur.fetchall()]

    # ---------------------------------------------------------------- writes
    def execute(self, sql: str, params: tuple | dict | None = None) -> dict | None:
        """Run a write; returns the first row when the statement has RETURNING."""
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            return _floats(cur.fetchone()) if cur.description else None

    @contextmanager
    def transaction(self):
        """Group several statements atomically: `with db.transaction(): ...` (nests as savepoints)."""
        with self.conn.transaction():
            yield self

    # ---------------------------------------------------------------- bulk load
    def run_script(self, path: Path) -> None:
        # No params -> sent as a simple query, so a multi-statement script (the schema) runs in one go
        with self.conn.cursor() as cur:
            cur.execute(Path(path).read_text(encoding="utf-8"))

    def copy_csv(self, table: str, path: Path) -> int:
        """Bulk-load a CSV with COPY, using its header row as the column list."""
        with open(path, newline="", encoding="utf-8") as f:
            header = next(csv.reader(f))
        cols = ", ".join(header)
        n = 0
        with self.conn.cursor() as cur, open(path, "rb") as f:
            with cur.copy(f"COPY {table} ({cols}) FROM STDIN WITH (FORMAT csv, HEADER true)") as cp:
                while chunk := f.read(1 << 20):   # stream in 1 MB chunks
                    cp.write(chunk)
            n = cur.rowcount
        return n

    def close(self):
        self.conn.close()


def _floats(row: dict | None) -> dict | None:
    """Decimal -> float in single-row results (amounts are shown and compared, never summed for ledgers here)."""
    if row is None:
        return None
    return {k: (float(v) if isinstance(v, Decimal) else v) for k, v in row.items()}
