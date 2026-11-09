"""The vulnerable sample API (expanded, multi-tenant).

Every seeded flaw is marked with a `SEEDED FLAW <id>` comment so the mapping to
`authz_tests/catalog.py` is explicit and auditable. The hardened version in
`secure.py` fixes each one.

OWASP API Security Top 10 (2023) coverage:
  SF-01  API1 BOLA     cross-user profile read (incl. ssn/salary)
  SF-02  API1 BOLA     cross-user order listing
  SF-03  API3 BOPLA    mass assignment of role (self-promotion)
  SF-04  API3 BOPLA    mass assignment of tenant (cross-tenant move)
  SF-05  API1 BOLA     cross-tenant document read (tenant isolation)
  SF-06  API5 BFLA     non-admin invokes admin-only delete
  SF-07  API5 BFLA     non-admin reads admin-only metrics
  SF-08  API5 BFLA     manager deletes a user OUTSIDE their tenant
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from .data import Store, fresh_store, make_token, read_token


class LoginBody(BaseModel):
    username: str


class PatchUser(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None       # exposing this is a mass-assignment bug
    tenant: Optional[str] = None     # exposing this is a mass-assignment bug
    salary: Optional[int] = None     # exposing this is a mass-assignment bug


def build_app() -> FastAPI:
    app = FastAPI(title="sample-api (vulnerable)")
    store: Store = fresh_store()

    def current_user(authorization: Optional[str]):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(401, "missing bearer token")
        username = read_token(authorization.split(" ", 1)[1])
        user = store.user_by_name(username) if username else None
        if not user:
            raise HTTPException(401, "invalid token")
        return user

    @app.post("/login")
    def login(body: LoginBody):
        user = store.user_by_name(body.username)
        if not user:
            raise HTTPException(404, "no such user")
        return {"token": make_token(user.username), "user_id": user.id}

    @app.get("/users/{user_id}")
    def get_user(user_id: int, authorization: Optional[str] = Header(default=None)):
        current_user(authorization)
        target = store.users.get(user_id)
        if not target:
            raise HTTPException(404, "not found")
        # SEEDED FLAW SF-01 (BOLA): returns ANY user's full record, including ssn
        # and salary, with no check that the caller may see this object.
        return target.__dict__

    @app.get("/users/{user_id}/orders")
    def get_orders(user_id: int, authorization: Optional[str] = Header(default=None)):
        current_user(authorization)
        # SEEDED FLAW SF-02 (BOLA): any authenticated user reads any user's orders.
        return [o.__dict__ for o in store.orders_for(user_id)]

    @app.patch("/users/{user_id}")
    def patch_user(user_id: int, body: PatchUser, authorization: Optional[str] = Header(default=None)):
        current_user(authorization)
        target = store.users.get(user_id)
        if not target:
            raise HTTPException(404, "not found")
        if body.email is not None:
            target.email = body.email
        # SEEDED FLAW SF-03 (BOPLA): client-supplied role written through -> self-promotion.
        if body.role is not None:
            target.role = body.role
        # SEEDED FLAW SF-04 (BOPLA): client-supplied tenant written through -> cross-tenant move.
        if body.tenant is not None:
            target.tenant = body.tenant
        if body.salary is not None:
            target.salary = body.salary
        return target.__dict__

    @app.get("/tenants/{tenant}/documents")
    def get_documents(tenant: str, authorization: Optional[str] = Header(default=None)):
        current_user(authorization)
        # SEEDED FLAW SF-05 (BOLA / tenant isolation): any user reads any tenant's docs.
        return [d.__dict__ for d in store.documents_for(tenant)]

    @app.delete("/admin/users/{user_id}")
    def delete_user(user_id: int, authorization: Optional[str] = Header(default=None)):
        current_user(authorization)
        # SEEDED FLAW SF-06 / SF-08 (BFLA): admin-only + tenant-scoped function with
        # no role or tenant check at all.
        if user_id in store.users:
            del store.users[user_id]
        return {"deleted": user_id}

    @app.get("/admin/metrics")
    def admin_metrics(authorization: Optional[str] = Header(default=None)):
        current_user(authorization)
        # SEEDED FLAW SF-07 (BFLA): admin-only data exposed to any authenticated user.
        return {"user_count": len(store.users),
                "total_salary": sum(u.salary for u in store.users.values())}

    return app


app = build_app()
