"""The hardened sample API - each seeded flaw from `vulnerable.py` is fixed.

Authorization model:
  * object-level: a user may read/edit their own objects; an admin may act on
    anything; a manager may act within their own tenant.
  * property-level: role / tenant / salary are never client-settable (BOPLA).
  * function-level: /admin/metrics is admin-only; delete is admin or a manager
    acting within their own tenant (BFLA + tenant scope).

Run the authorization tests against this app and they should report zero
successful forbidden actions AND zero wrongly-denied legitimate actions.
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from .data import Store, User, fresh_store, make_token, read_token


class LoginBody(BaseModel):
    username: str


class PatchUser(BaseModel):
    email: Optional[str] = None
    # role / tenant / salary are deliberately NOT accepted — not client-settable.


def build_app() -> FastAPI:
    app = FastAPI(title="sample-api (secure)")
    store: Store = fresh_store()

    def current_user(authorization: Optional[str]) -> User:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing bearer token")
        username = read_token(authorization.split(" ", 1)[1])
        user = store.user_by_name(username) if username else None
        if not user:
            raise HTTPException(401, "invalid token")
        return user

    # --- authorization helpers ---
    def can_read_user(caller: User, target: User) -> bool:
        return (caller.id == target.id
                or caller.role == "admin"
                or (caller.role == "manager" and caller.tenant == target.tenant))

    def can_edit_user(caller: User, target: User) -> bool:
        return caller.id == target.id or caller.role == "admin"

    def can_read_tenant(caller: User, tenant: str) -> bool:
        return caller.role == "admin" or caller.tenant == tenant

    def can_delete_user(caller: User, target: User) -> bool:
        return (caller.role == "admin"
                or (caller.role == "manager" and caller.tenant == target.tenant))

    def require(cond: bool):
        if not cond:
            raise HTTPException(403, "not authorized")

    @app.post("/login")
    def login(body: LoginBody):
        user = store.user_by_name(body.username)
        if not user:
            raise HTTPException(404, "no such user")
        return {"token": make_token(user.username), "user_id": user.id}

    @app.get("/users/{user_id}")
    def get_user(user_id: int, authorization: Optional[str] = Header(default=None)):
        caller = current_user(authorization)
        target = store.users.get(user_id)
        if not target:
            raise HTTPException(404, "not found")
        require(can_read_user(caller, target))                 # FIX SF-01
        return target.__dict__

    @app.get("/users/{user_id}/orders")
    def get_orders(user_id: int, authorization: Optional[str] = Header(default=None)):
        caller = current_user(authorization)
        target = store.users.get(user_id)
        if not target:
            raise HTTPException(404, "not found")
        require(can_read_user(caller, target))                 # FIX SF-02
        return [o.__dict__ for o in store.orders_for(user_id)]

    @app.patch("/users/{user_id}")
    def patch_user(user_id: int, body: PatchUser, authorization: Optional[str] = Header(default=None)):
        caller = current_user(authorization)
        target = store.users.get(user_id)
        if not target:
            raise HTTPException(404, "not found")
        require(can_edit_user(caller, target))
        if body.email is not None:
            target.email = body.email
        # FIX SF-03 / SF-04: role, tenant and salary are not in the accepted model.
        return target.__dict__

    @app.get("/tenants/{tenant}/documents")
    def get_documents(tenant: str, authorization: Optional[str] = Header(default=None)):
        caller = current_user(authorization)
        require(can_read_tenant(caller, tenant))               # FIX SF-05
        return [d.__dict__ for d in store.documents_for(tenant)]

    @app.delete("/admin/users/{user_id}")
    def delete_user(user_id: int, authorization: Optional[str] = Header(default=None)):
        caller = current_user(authorization)
        target = store.users.get(user_id)
        if not target:
            raise HTTPException(404, "not found")
        require(can_delete_user(caller, target))               # FIX SF-06 / SF-08
        del store.users[user_id]
        return {"deleted": user_id}

    @app.get("/admin/metrics")
    def admin_metrics(authorization: Optional[str] = Header(default=None)):
        caller = current_user(authorization)
        require(caller.role == "admin")                        # FIX SF-07
        return {"user_count": len(store.users),
                "total_salary": sum(u.salary for u in store.users.values())}

    return app


app = build_app()
