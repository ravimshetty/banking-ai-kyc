"""Central configuration. Every threshold a risk/compliance team would want to tune lives here."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Settings come from environment variables. If python-dotenv is installed and a .env file exists next to this
# file, it is loaded first (variables already set in the shell win). Copy .env.example to .env to start.
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=False)
except ImportError:
    pass
DATA_DIR = ROOT / "data"
KB_DIR = ROOT / "kb"
SCHEMA_SQL = ROOT / "db" / "schema.sql"
RBAC_SEED_SQL = ROOT / "db" / "rbac_seed.sql"

# ---- PostgreSQL ----
# Matches docker-compose.yml; override with DATABASE_URL for any other server (RDS, Cloud SQL, Azure ...)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://bank:bank@localhost:5432/banking_ai")

SEED = 42
CURRENCY = "INR"

# ---- LLM (optional). Without a key the system runs fully deterministic. ----
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
USE_LLM = bool(OPENAI_API_KEY) and os.getenv("BANKING_AI_OFFLINE", "0") != "1"

# ---- Customer-reported card misuse (rationale shown to the analyst who approves a permanent block) ----
UNUSUAL_AMOUNT_MULTIPLE = 3.0      # "amount is Nx the customer's typical spend" when at least this
NIGHT_HOURS = {23, 0, 1, 2, 3, 4}

# ---- AML / KYC ----
CASH_REPORTING_THRESHOLD = 50_000  # PAN required at this level; structuring = repeated deposits just under it
STRUCTURING_BAND = 0.10            # "just under" = within 10% below threshold
STRUCTURING_MIN_COUNT = 3
STRUCTURING_WINDOW_DAYS = 7
RAPID_MOVEMENT_HOURS = 24
RAPID_MOVEMENT_RATIO = 0.80        # >=80% of a large credit moved out within the window
RAPID_MOVEMENT_MIN_AMOUNT = 200_000
HIGH_RISK_COUNTRIES = {"KP", "IR", "MM", "SY"}
SANCTIONS_MATCH_THRESHOLD = 0.85
