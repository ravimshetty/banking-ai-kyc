"""Create the schema and bulk-load the generated CSVs into PostgreSQL.

    python -m db.load            # drops and recreates every table, then loads data/*.csv

Re-running resets the bank to its starting state (card statuses, disputes, approvals, audit log).
"""
import config
from bank.db import Database
from data import generate

# Parent tables first so foreign keys are satisfied
LOAD_ORDER = ["customers", "accounts", "transactions", "sanctions"]


def main(db: Database | None = None) -> dict:
    if not (config.DATA_DIR / "transactions.csv").exists():
        generate.main()
    db = db or Database()
    db.run_script(config.SCHEMA_SQL)
    counts = {}
    with db.transaction():                         # all tables load, or none do
        for table in LOAD_ORDER:
            counts[table] = db.copy_csv(table, config.DATA_DIR / f"{table}.csv")
        db.run_script(config.RBAC_SEED_SQL)          # roles, permissions, staff + customer logins
    db.execute("ANALYZE")                          # fresh planner statistics after a bulk load
    counts["users"] = db.one("SELECT count(*) AS n FROM users")["n"]
    print("Loaded into PostgreSQL: " + ", ".join(f"{t}={n}" for t, n in counts.items()))
    return counts


if __name__ == "__main__":
    main()
