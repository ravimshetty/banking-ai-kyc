"""Role-based access control for the orchestrator.

Who can do what is data in PostgreSQL (roles, permissions, role_permissions, users, user_roles,
role_conflicts; see db/schema.sql and db/rbac_seed.sql). This module turns it into decisions:

    principal = rbac.load("cmp_02")                      # identity -> roles -> permissions
    rbac.require(principal, "account.read", "C0042")     # scoped: needs :any, or :own on their own data
    rbac.allowed_intents(principal)                      # what the router may even consider

Rules
- Deny by default: unknown, inactive or role-less users can do nothing.
- Scoped permissions: 'x:any' covers every customer; 'x:own' only the user's own customer_id.
- Approval rights are per action ('approval.decide:FILE_SAR'), and never on your own request (maker-checker).
- Segregation of duties is enforced by a database trigger, so it holds whatever path grants a role.
- Admins cannot change their own roles (no self-escalation). Every grant and revoke is audited.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from bank.db import Database, DatabaseError

# Which permission each orchestrator intent needs. Scoped ones are checked against the target customer.
INTENT_PERMISSIONS: dict[str, tuple[str, bool]] = {   # intent -> (permission, scoped_to_customer)
    "balance": ("account.read", True),
    "recent_transactions": ("txn.read", True),
    "freeze_card": ("card.freeze", True),
    "dispute": ("dispute.create", True),
    "report_fraud": ("fraud.report", True),
    "kyc_status": ("kyc.read", True),
    "policy_question": ("policy.read", False),
    "aml_review": ("aml.review", False),
}
OPEN_INTENTS = {"smalltalk"}            # no permission needed: explains what the assistant can do


class AccessDenied(PermissionError):
    def __init__(self, user_id: str | None, permission: str, reason: str):
        super().__init__(reason)
        self.user_id, self.permission, self.reason = user_id, permission, reason


@dataclass(frozen=True)
class Principal:
    user_id: str
    display_name: str
    customer_id: str | None          # set for customer logins: the only customer they may see
    roles: frozenset[str]
    permissions: frozenset[str]

    @property
    def is_customer(self) -> bool:
        return self.customer_id is not None


class RBAC:
    def __init__(self, db: Database, cache_ttl_seconds: float = 30.0):
        self.db = db
        self.ttl = cache_ttl_seconds
        self._cache: dict[str, tuple[float, Principal]] = {}

    # ------------------------------------------------------------------ identity
    def load(self, user_id: str | None) -> Principal:
        """Resolve a user to their roles and permissions. Cached briefly; grants/revokes invalidate."""
        if not user_id:
            raise AccessDenied(user_id, "login", "No user identity supplied")
        hit = self._cache.get(user_id)
        if hit and time.monotonic() - hit[0] < self.ttl:
            return hit[1]
        user = self.db.one("SELECT user_id, display_name, customer_id, active FROM users WHERE user_id = %s",
                           (user_id,))
        if user is None:
            raise AccessDenied(user_id, "login", f"Unknown user {user_id}")
        if not user["active"]:
            raise AccessDenied(user_id, "login", f"User {user_id} is deactivated")
        rows = self.db.all(
            "SELECT ur.role, rp.permission "
            "FROM user_roles ur JOIN roles r USING (role) "
            "LEFT JOIN role_permissions rp USING (role) WHERE ur.user_id = %s", (user_id,))
        if not rows:
            raise AccessDenied(user_id, "login", f"User {user_id} has no roles")
        roles = frozenset(r["role"] for r in rows)
        perms = frozenset(r["permission"] for r in rows if r["permission"])
        p = Principal(user["user_id"], user["display_name"], user["customer_id"], roles, perms)
        self._cache[user_id] = (time.monotonic(), p)
        return p

    def invalidate(self, user_id: str | None = None) -> None:
        if user_id is None:
            self._cache.clear()
        else:
            self._cache.pop(user_id, None)

    # ------------------------------------------------------------------ decisions
    def can(self, p: Principal, permission: str, customer_id: str | None = None) -> bool:
        if permission in p.permissions:                      # unscoped permission
            return True
        if f"{permission}:any" in p.permissions:
            return True
        return (f"{permission}:own" in p.permissions and customer_id is not None
                and customer_id == p.customer_id)

    def require(self, p: Principal, permission: str, customer_id: str | None = None) -> None:
        if not self.can(p, permission, customer_id):
            target = f" for customer {customer_id}" if customer_id else ""
            raise AccessDenied(p.user_id, permission, f"{p.user_id} lacks {permission}{target}")

    def allowed_intents(self, p: Principal) -> list[str]:
        """Intents this user could ever run (scoped ones on at least their own data)."""
        out = sorted(OPEN_INTENTS)
        for intent, (perm, scoped) in INTENT_PERMISSIONS.items():
            if perm in p.permissions or (scoped and (f"{perm}:any" in p.permissions or f"{perm}:own" in p.permissions)):
                out.append(intent)
        return out

    def require_intent(self, p: Principal, intent: str, customer_id: str | None) -> None:
        if intent in OPEN_INTENTS:
            return
        perm, scoped = INTENT_PERMISSIONS[intent]
        self.require(p, perm, customer_id if scoped else None)

    def require_approval(self, p: Principal, item: dict) -> None:
        """May this user decide this approval item? The action right, and not their own request."""
        self.require(p, f"approval.decide:{item['action']}")
        if item.get("requested_by") == p.user_id:
            raise AccessDenied(p.user_id, f"approval.decide:{item['action']}",
                               "Maker-checker: you requested this action, so someone else must approve it")

    def can_decide(self, p: Principal, item: dict) -> bool:
        try:
            self.require_approval(p, item)
            return True
        except AccessDenied:
            return False

    # ------------------------------------------------------------------ administration
    def grant(self, admin: Principal, user_id: str, role: str, audit=None) -> None:
        self._admin_check(admin, user_id)
        with self.db.transaction():
            # lock the user row so two concurrent grants can't jointly break segregation of duties
            if self.db.one("SELECT 1 AS ok FROM users WHERE user_id = %s FOR UPDATE", (user_id,)) is None:
                raise KeyError(f"Unknown user {user_id}")
            try:
                self.db.execute("INSERT INTO user_roles (user_id, role, granted_by) VALUES (%s, %s, %s) "
                                "ON CONFLICT DO NOTHING", (user_id, role, admin.user_id))
            except DatabaseError as e:   # the segregation-of-duties trigger (or an unknown role) said no
                raise AccessDenied(admin.user_id, "rbac.admin", _db_reason(e)) from e
            if audit:
                audit.write("role_granted", user=user_id, role=role, by=admin.user_id)
        self.invalidate(user_id)

    def revoke(self, admin: Principal, user_id: str, role: str, audit=None) -> None:
        self._admin_check(admin, user_id)
        with self.db.transaction():
            self.db.execute("DELETE FROM user_roles WHERE user_id = %s AND role = %s", (user_id, role))
            if audit:
                audit.write("role_revoked", user=user_id, role=role, by=admin.user_id)
        self.invalidate(user_id)

    def set_active(self, admin: Principal, user_id: str, active: bool, audit=None) -> None:
        self._admin_check(admin, user_id)
        with self.db.transaction():
            self.db.execute("UPDATE users SET active = %s WHERE user_id = %s", (active, user_id))
            if audit:
                audit.write("user_activated" if active else "user_deactivated", user=user_id, by=admin.user_id)
        self.invalidate(user_id)

    def create_user(self, admin: Principal, user_id: str, display_name: str, roles: list[str], audit=None) -> None:
        self.require(admin, "rbac.admin")
        with self.db.transaction():
            try:
                self.db.execute("INSERT INTO users (user_id, display_name) VALUES (%s, %s)", (user_id, display_name))
                for role in roles:
                    self.db.execute("INSERT INTO user_roles (user_id, role, granted_by) VALUES (%s, %s, %s)",
                                    (user_id, role, admin.user_id))
            except DatabaseError as e:   # duplicate user, unknown role, or a segregation-of-duties clash
                raise AccessDenied(admin.user_id, "rbac.admin", _db_reason(e)) from e
            if audit:
                audit.write("user_created", user=user_id, roles=roles, by=admin.user_id)

    def _admin_check(self, admin: Principal, user_id: str) -> None:
        self.require(admin, "rbac.admin")
        if user_id == admin.user_id:
            raise AccessDenied(admin.user_id, "rbac.admin", "Admins cannot change their own access")

    def matrix(self) -> list[dict]:
        """Role x permission listing, for reviews and docs."""
        return self.db.all("SELECT r.role, r.description, "
                           "COALESCE(string_agg(rp.permission, ', ' ORDER BY rp.permission), '') AS permissions "
                           "FROM roles r LEFT JOIN role_permissions rp USING (role) GROUP BY r.role, "
                           "r.description ORDER BY r.role")


def _db_reason(e: Exception) -> str:
    """First line of a database error, e.g. 'segregation of duties: mlro conflicts with rbac_admin ...'."""
    msg = str(e)
    if "ERROR:" in msg:                      # psql-style prefix
        msg = msg.split("ERROR:", 1)[1]
    return msg.strip().splitlines()[0].split(" | ")[0].strip()
