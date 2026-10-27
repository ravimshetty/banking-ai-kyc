"""REST API. Run: uvicorn api:app --reload   then open http://127.0.0.1:8000/docs

Callers identify themselves with X-User only; their roles and permissions are looked up in PostgreSQL
(bank/rbac.py), never taken from the request. In production, put this behind your identity provider
(OAuth2/OIDC) and take the user id from the verified token instead of a header."""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from bank.agents import BankingAgents
from bank.rbac import AccessDenied

app = FastAPI(title="Banking AI: Customer Service + KYC/AML", version="3.0")
bank = BankingAgents()


class ChatIn(BaseModel):
    message: str
    customer_id: str | None = None   # staff: which customer the request is about


class DecisionIn(BaseModel):
    approve: bool
    note: str = ""


class RoleIn(BaseModel):
    role: str


class UserIn(BaseModel):
    user_id: str
    display_name: str
    roles: list[str]


def _guard(fn):
    """Map RBAC and lookup failures to HTTP status codes."""
    try:
        return fn()
    except AccessDenied as e:
        raise HTTPException(403, e.reason)
    except KeyError as e:
        raise HTTPException(404, str(e).strip("'"))
    except (ValueError, PermissionError) as e:
        raise HTTPException(409, str(e))


@app.get("/me")
def me(x_user: str = Header(...)):
    def run():
        p = bank.rbac.load(x_user)
        return {"user_id": p.user_id, "display_name": p.display_name, "customer_id": p.customer_id,
                "roles": sorted(p.roles), "permissions": sorted(p.permissions),
                "intents": bank.rbac.allowed_intents(p)}
    return _guard(run)


@app.post("/chat")
def chat(body: ChatIn, x_user: str = Header(...)):
    return bank.handle(body.message, user_id=x_user, customer_id=body.customer_id)


@app.get("/approvals")
def approvals(x_user: str = Header(...)):
    """Your approval inbox: only items you are allowed to decide."""
    return _guard(lambda: bank.pending_for(x_user))


@app.post("/approvals/{approval_id}")
def decide(approval_id: str, body: DecisionIn, x_user: str = Header(...)):
    return _guard(lambda: bank.decide(approval_id, user_id=x_user, approve=body.approve, note=body.note))


@app.get("/audit")
def audit(limit: int = 50, x_user: str = Header(...)):
    return _guard(lambda: bank.audit_events(x_user, limit))


# ---------------------------------------------------------------- access administration (rbac.admin only)
@app.get("/admin/roles")
def role_matrix(x_user: str = Header(...)):
    def run():
        bank.rbac.require(bank.rbac.load(x_user), "rbac.admin")
        return bank.rbac.matrix()
    return _guard(run)


@app.post("/admin/users")
def create_user(body: UserIn, x_user: str = Header(...)):
    return _guard(lambda: bank.rbac.create_user(bank.rbac.load(x_user), body.user_id, body.display_name,
                                                body.roles, audit=bank.audit) or {"created": body.user_id})


@app.post("/admin/users/{user_id}/roles")
def grant_role(user_id: str, body: RoleIn, x_user: str = Header(...)):
    return _guard(lambda: bank.rbac.grant(bank.rbac.load(x_user), user_id, body.role, audit=bank.audit)
                  or {"granted": body.role, "user_id": user_id})


@app.delete("/admin/users/{user_id}/roles/{role}")
def revoke_role(user_id: str, role: str, x_user: str = Header(...)):
    return _guard(lambda: bank.rbac.revoke(bank.rbac.load(x_user), user_id, role, audit=bank.audit)
                  or {"revoked": role, "user_id": user_id})


@app.post("/admin/users/{user_id}/deactivate")
def deactivate(user_id: str, x_user: str = Header(...)):
    return _guard(lambda: bank.rbac.set_active(bank.rbac.load(x_user), user_id, False, audit=bank.audit)
                  or {"deactivated": user_id})


@app.get("/health")
def health():
    return {"status": "ok", "llm": bank.llm.enabled}
