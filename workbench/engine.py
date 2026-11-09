"""Drive an arbitrary request against both APIs in-process and compare.

No network listener is opened for the APIs themselves: each request is executed
with Starlette's TestClient against a freshly-built app, so there is no residual
state between workbench runs.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from fastapi.testclient import TestClient

from authz_tests.catalog import PROBES, ROLE
from authz_tests.policies import policy_for
from sample_api import secure, vulnerable


def _run_one(build_app, user: Optional[str], method: str, path: str, body: Optional[dict]) -> Dict:
    client = TestClient(build_app())
    headers = {}
    if user:
        r = client.post("/login", json={"username": user})
        if r.status_code == 200:
            headers = {"Authorization": "Bearer " + r.json()["token"]}
    m = method.upper()
    if m == "GET":
        resp = client.get(path, headers=headers)
    elif m == "DELETE":
        resp = client.delete(path, headers=headers)
    elif m == "PATCH":
        resp = client.patch(path, headers=headers, json=body or {})
    elif m == "POST":
        resp = client.post(path, headers=headers, json=body or {})
    else:
        return {"error": "unsupported method %s" % method}
    try:
        payload = resp.json()
    except Exception:
        payload = resp.text
    return {
        "status": resp.status_code,
        "allowed": 200 <= resp.status_code < 300,
        "body": payload,
    }


def run_request(user: Optional[str], method: str, path: str, body: Optional[dict] = None) -> Dict:
    vuln = _run_one(vulnerable.build_app, user, method, path, body)
    sec = _run_one(secure.build_app, user, method, path, body)
    role, tenant = ROLE.get(user, ("?", "?")) if user else ("anonymous", "-")
    # Interpretation: vulnerable allows but secure blocks => the fix stops this.
    if vuln["allowed"] and not sec["allowed"]:
        verdict = "fix_blocks"          # the vulnerable app leaks; the fix prevents it
    elif vuln["allowed"] and sec["allowed"]:
        verdict = "both_allow"          # a legitimate action (or both vulnerable)
    elif not vuln["allowed"] and not sec["allowed"]:
        verdict = "both_block"
    else:
        verdict = "only_secure_allows"  # unusual
    return {
        "request": {"user": user, "role": role, "tenant": tenant,
                    "method": method.upper(), "path": path, "body": body},
        "vulnerable": vuln,
        "secure": sec,
        "verdict": verdict,
        "policy": policy_for(method, path),
    }


def catalogue() -> Dict:
    """Static data the UI needs: users, endpoint presets, and probe scenarios."""
    users = [{"username": u, "role": r, "tenant": t} for u, (r, t) in ROLE.items()]
    endpoints = [
        {"method": "GET", "path": "/users/1", "label": "Read user 1 (alice) profile"},
        {"method": "GET", "path": "/users/1/orders", "label": "List user 1 orders"},
        {"method": "PATCH", "path": "/users/2", "label": "Update user 2",
         "body": {"email": "x@acme.example"}},
        {"method": "GET", "path": "/tenants/acme/documents", "label": "Read acme documents"},
        {"method": "DELETE", "path": "/admin/users/3", "label": "Delete user 3 (carol)"},
        {"method": "GET", "path": "/admin/metrics", "label": "Read admin metrics"},
    ]
    scenarios = [
        {"probe_id": p.probe_id, "kind": p.kind, "title": p.title, "caller": p.caller,
         "method": p.method, "path": p.path, "body": p.body, "seeded_flaw": p.seeded_flaw,
         "owasp": p.owasp, "route": p.route}
        for p in PROBES
    ]
    return {"users": users, "endpoints": endpoints, "scenarios": scenarios}
