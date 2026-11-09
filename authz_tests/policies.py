"""Human-readable authorization policy per route, for the workbench to show
alongside each request/response comparison."""

from __future__ import annotations

import re
from typing import Dict, Optional

POLICIES: Dict[str, Dict] = {
    "GET /users/{id}": {
        "owasp": "API1:2023 Broken Object Level Authorization (BOLA)",
        "rule": "A user may read only their own profile. An admin may read any "
                "profile; a manager may read profiles within their own tenant. "
                "Sensitive fields (ssn, salary) must never leak cross-user.",
        "secure": "require(can_read_user(caller, target))",
    },
    "GET /users/{id}/orders": {
        "owasp": "API1:2023 BOLA",
        "rule": "Order lists follow the same object-level rule as the profile: "
                "owner, admin, or a manager in the same tenant.",
        "secure": "require(can_read_user(caller, target))",
    },
    "PATCH /users/{id}": {
        "owasp": "API3:2023 Broken Object Property Level Authorization (mass assignment)",
        "rule": "A user may edit their own editable fields (email). role, tenant "
                "and salary are NOT client-settable — the secure model simply does "
                "not accept them.",
        "secure": "PatchUser has only `email`; require(can_edit_user(caller, target))",
    },
    "GET /tenants/{t}/documents": {
        "owasp": "API1:2023 BOLA (tenant isolation)",
        "rule": "Only members of a tenant (or an admin) may read that tenant's "
                "documents. Cross-tenant reads must be blocked.",
        "secure": "require(can_read_tenant(caller, tenant))",
    },
    "DELETE /admin/users/{id}": {
        "owasp": "API5:2023 Broken Function Level Authorization (BFLA)",
        "rule": "Deleting a user is admin-only, except a manager may delete a user "
                "within their own tenant. A user, or a manager acting outside their "
                "tenant, must be denied.",
        "secure": "require(can_delete_user(caller, target))",
    },
    "GET /admin/metrics": {
        "owasp": "API5:2023 BFLA",
        "rule": "Organization-wide metrics are admin-only.",
        "secure": "require(caller.role == 'admin')",
    },
}

_PATTERNS = [
    (re.compile(r"^/users/\d+/orders/?$"), "/users/{id}/orders"),
    (re.compile(r"^/users/\d+/?$"), "/users/{id}"),
    (re.compile(r"^/tenants/[^/]+/documents/?$"), "/tenants/{t}/documents"),
    (re.compile(r"^/admin/users/\d+/?$"), "/admin/users/{id}"),
    (re.compile(r"^/admin/metrics/?$"), "/admin/metrics"),
]


def route_key(method: str, path: str) -> str:
    path = path.split("?")[0]
    for pat, templ in _PATTERNS:
        if pat.match(path):
            return "%s %s" % (method.upper(), templ)
    return "%s %s" % (method.upper(), path)


def policy_for(method: str, path: str) -> Optional[Dict]:
    return POLICIES.get(route_key(method, path))
