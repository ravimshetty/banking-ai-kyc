-- Banking AI — PostgreSQL schema (PostgreSQL 13+).
-- Run via `python -m db.load` (drops and recreates everything) or `psql -f db/schema.sql`.

DROP TABLE IF EXISTS audit_log, approvals, disputes, loan_applications, loan_history,  -- loan tables: older versions
                     transactions, accounts, user_roles, users, role_permissions, role_conflicts,
                     permissions, roles, customers, sanctions CASCADE;
DROP SEQUENCE IF EXISTS dispute_seq;

-- ---------------------------------------------------------------- reference / master data
CREATE TABLE customers (
    customer_id       TEXT PRIMARY KEY,
    name              TEXT          NOT NULL,
    age               INTEGER       NOT NULL CHECK (age BETWEEN 18 AND 120),
    monthly_income    NUMERIC(14,2) NOT NULL CHECK (monthly_income >= 0),
    employment_years  INTEGER       NOT NULL CHECK (employment_years >= 0),
    home_country      CHAR(2)       NOT NULL,
    kyc_status        TEXT          NOT NULL CHECK (kyc_status IN ('VERIFIED', 'PENDING_REKYC')),
    segment           TEXT          NOT NULL CHECK (segment IN ('RETAIL', 'PREMIUM'))
);

CREATE TABLE accounts (
    account_id   TEXT PRIMARY KEY,
    customer_id  TEXT NOT NULL UNIQUE REFERENCES customers(customer_id),
    balance      NUMERIC(14,2) NOT NULL,
    card_id      TEXT NOT NULL UNIQUE,
    card_status  TEXT NOT NULL CHECK (card_status IN ('ACTIVE', 'TEMP_FROZEN', 'BLOCKED')),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE transactions (
    txn_id             TEXT PRIMARY KEY,
    customer_id        TEXT NOT NULL REFERENCES customers(customer_id),
    ts                 TIMESTAMP NOT NULL,
    amount             NUMERIC(14,2) NOT NULL CHECK (amount >= 0),
    direction          TEXT NOT NULL CHECK (direction IN ('DEBIT', 'CREDIT')),
    channel            TEXT NOT NULL,
    merchant_category  TEXT NOT NULL,
    country            CHAR(2) NOT NULL,
    new_device         BOOLEAN NOT NULL,
    counterparty       TEXT NOT NULL,
    is_fraud           SMALLINT NOT NULL DEFAULT 0 CHECK (is_fraud IN (0, 1))  -- planted misuse (synthetic data only)
);
-- a customer's history by time (every agent reads this), and debits by time for back-office reporting
CREATE INDEX ix_txn_customer_ts ON transactions (customer_id, ts DESC);
CREATE INDEX ix_txn_ts_debit    ON transactions (ts) WHERE direction = 'DEBIT';

CREATE TABLE sanctions (
    name      TEXT NOT NULL,
    list      TEXT NOT NULL,
    PRIMARY KEY (name, list)
);

-- ---------------------------------------------------------------- access control (RBAC)
-- Roles and permissions are data, not code: change who can do what with SQL or the admin API.
CREATE TABLE roles (
    role                 TEXT PRIMARY KEY,
    description          TEXT NOT NULL
);

CREATE TABLE permissions (
    permission   TEXT PRIMARY KEY,      -- 'resource.action' or 'resource.action:own|any' for customer-scoped data
    description  TEXT NOT NULL
);

CREATE TABLE role_permissions (
    role        TEXT NOT NULL REFERENCES roles(role) ON DELETE CASCADE,
    permission  TEXT NOT NULL REFERENCES permissions(permission),
    PRIMARY KEY (role, permission)
);

-- Segregation of duties: pairs of roles one person may never hold together
CREATE TABLE role_conflicts (
    role_a  TEXT NOT NULL REFERENCES roles(role) ON DELETE CASCADE,
    role_b  TEXT NOT NULL REFERENCES roles(role) ON DELETE CASCADE,
    reason  TEXT NOT NULL,
    PRIMARY KEY (role_a, role_b),
    CHECK (role_a < role_b)              -- store each pair once
);

CREATE TABLE users (
    user_id       TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL,
    customer_id   TEXT UNIQUE REFERENCES customers(customer_id),   -- set only for customer logins
    active        BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_roles (
    user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role        TEXT NOT NULL REFERENCES roles(role),
    granted_by  TEXT NOT NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role)
);

-- The database refuses a role grant that breaks segregation of duties, whoever issues it
CREATE OR REPLACE FUNCTION enforce_segregation_of_duties() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE clash TEXT;
BEGIN
    SELECT ur.role INTO clash
    FROM user_roles ur
    JOIN role_conflicts rc
      ON (rc.role_a = NEW.role AND rc.role_b = ur.role) OR (rc.role_b = NEW.role AND rc.role_a = ur.role)
    WHERE ur.user_id = NEW.user_id
    LIMIT 1;
    IF clash IS NOT NULL THEN
        RAISE EXCEPTION 'segregation of duties: % conflicts with % already held by %', NEW.role, clash, NEW.user_id;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_user_roles_sod
    BEFORE INSERT OR UPDATE ON user_roles
    FOR EACH ROW EXECUTE FUNCTION enforce_segregation_of_duties();

-- ---------------------------------------------------------------- operations
CREATE SEQUENCE dispute_seq;
CREATE TABLE disputes (
    dispute_id   TEXT PRIMARY KEY DEFAULT ('D' || lpad(nextval('dispute_seq')::text, 4, '0')),
    customer_id  TEXT NOT NULL REFERENCES customers(customer_id),
    txn_id       TEXT NOT NULL REFERENCES transactions(txn_id),
    amount       NUMERIC(14,2) NOT NULL,
    reason       TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'RESOLVED', 'REJECTED')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_disputes_customer ON disputes (customer_id);

-- Human-in-the-loop queue. Persisted, so pending approvals survive restarts.
CREATE TABLE approvals (
    approval_id  TEXT PRIMARY KEY,
    action       TEXT NOT NULL CHECK (action IN ('BLOCK_CARD_PERMANENT', 'FILE_SAR')),
    payload      JSONB NOT NULL,
    proposed_by  TEXT NOT NULL,                              -- the agent that drafted it
    requested_by TEXT NOT NULL REFERENCES users(user_id),    -- the human whose request led to it
    rationale    TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    approver     TEXT REFERENCES users(user_id),
    note         TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at   TIMESTAMPTZ,
    -- maker-checker enforced by the database too, not only by application code
    CONSTRAINT approver_is_not_proposer CHECK (approver IS NULL OR approver <> proposed_by),
    CONSTRAINT approver_is_not_requester CHECK (approver IS NULL OR approver <> requested_by),
    CONSTRAINT decided_fields CHECK ((status = 'PENDING') = (approver IS NULL AND decided_at IS NULL))
);
CREATE INDEX ix_approvals_pending ON approvals (created_at) WHERE status = 'PENDING';

-- Append-only audit trail: UPDATE and DELETE are rejected by a trigger.
CREATE TABLE audit_log (
    id       BIGSERIAL PRIMARY KEY,
    ts       TIMESTAMPTZ NOT NULL DEFAULT now(),
    event    TEXT NOT NULL,
    details  JSONB NOT NULL
);
CREATE INDEX ix_audit_event_ts ON audit_log (event, ts);

CREATE OR REPLACE FUNCTION audit_log_is_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only (% not allowed)', TG_OP;
END $$;

CREATE TRIGGER trg_audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_is_append_only();
