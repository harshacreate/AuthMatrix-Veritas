"""A deliberately over-restrictive API: it denies every protected request.

This is the control the scoring must NOT mistake for secure. It blocks all the
forbidden probes (so a naive "did it reject the attacks?" metric would call it
perfect), but it also blocks every legitimate request. The runner's precision and
specificity therefore collapse, which is exactly the point: rejecting everything
is not the same as being correctly authorized.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .data import fresh_store, make_token


class LoginBody(BaseModel):
    username: str


def build_app() -> FastAPI:
    app = FastAPI(title="sample-api (deny-all control)")
    store = fresh_store()

    @app.post("/login")
    def login(body: LoginBody):
        user = store.user_by_name(body.username)
        if not user:
            raise HTTPException(404, "no such user")
        return {"token": make_token(user.username), "user_id": user.id}

    # Every protected route denies, regardless of caller.
    @app.get("/users/{user_id}")
    def get_user(user_id: int):
        raise HTTPException(403, "denied")

    @app.get("/users/{user_id}/orders")
    def get_orders(user_id: int):
        raise HTTPException(403, "denied")

    @app.patch("/users/{user_id}")
    def patch_user(user_id: int):
        raise HTTPException(403, "denied")

    @app.get("/tenants/{tenant}/documents")
    def get_documents(tenant: str):
        raise HTTPException(403, "denied")

    @app.delete("/admin/users/{user_id}")
    def delete_user(user_id: int):
        raise HTTPException(403, "denied")

    @app.get("/admin/metrics")
    def admin_metrics():
        raise HTTPException(403, "denied")

    return app


app = build_app()
