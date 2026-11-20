"""This sample API has known access bugs. Comments mark each bug with its ID and link it to the
checks in `authz_tests/catalog.py`. The fixed version is in `secure.py`. The bugs cover
OWASP API Security Top 10 (2023) issues: reading another user's profile or orders, changing
a role or company, reading another company's files, using admin actions without permission,
and deleting a user outside the manager's company.
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
        # Bug SF-01: any user can read another user's full record, including
        # private fields such as SSN and salary.
        return target.__dict__

    @app.get("/users/{user_id}/orders")
    def get_orders(user_id: int, authorization: Optional[str] = Header(default=None)):
        current_user(authorization)
        # Bug SF-02: any signed-in user can read another user's orders.
        return [o.__dict__ for o in store.orders_for(user_id)]

    @app.patch("/users/{user_id}")
    def patch_user(user_id: int, body: PatchUser, authorization: Optional[str] = Header(default=None)):
        current_user(authorization)
        target = store.users.get(user_id)
        if not target:
            raise HTTPException(404, "not found")
        if body.email is not None:
            target.email = body.email
        # Bug SF-03: a user can change their own role.
        if body.role is not None:
            target.role = body.role
        # Bug SF-04: a user can move themselves to another company.
        if body.tenant is not None:
            target.tenant = body.tenant
        if body.salary is not None:
            target.salary = body.salary
        return target.__dict__

    @app.get("/tenants/{tenant}/documents")
    def get_documents(tenant: str, authorization: Optional[str] = Header(default=None)):
        current_user(authorization)
        # Bug SF-05: any user can read another company's files.
        return [d.__dict__ for d in store.documents_for(tenant)]

    @app.delete("/admin/users/{user_id}")
    def delete_user(user_id: int, authorization: Optional[str] = Header(default=None)):
        current_user(authorization)
        # Bugs SF-06 and SF-08: this route does not check the caller's role or
        # company before deleting a user.
        if user_id in store.users:
            del store.users[user_id]
        return {"deleted": user_id}

    @app.get("/admin/metrics")
    def admin_metrics(authorization: Optional[str] = Header(default=None)):
        current_user(authorization)
        # Bug SF-07: any signed-in user can read admin data.
        return {"user_count": len(store.users),
                "total_salary": sum(u.salary for u in store.users.values())}

    return app


app = build_app()
