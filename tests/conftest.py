"""pytest setup, shared by the command line and the VS Code Test Explorer.

Runs ONCE per test session, before the first test (never during test discovery):
  1. forces offline mode, so tests are deterministic even if OPENAI_API_KEY is set in .env
  2. resets PostgreSQL to the seeded starting state (tables, users, roles; no disputes/approvals/audit rows)
"""
import os
import sys
from pathlib import Path

os.environ["BANKING_AI_OFFLINE"] = "1"                 # before config is imported anywhere
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

import config  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def fresh_bank():
    from bank.db import Database
    from db import load
    try:
        Database().one("SELECT 1 AS ok")
    except Exception as e:  # noqa: BLE001
        pytest.exit(f"Cannot connect to PostgreSQL at {config.DATABASE_URL}: {e}\n"
                    "Start it with `docker compose up -d` (or check DATABASE_URL in .env).", returncode=2)
    load.main()
    yield
