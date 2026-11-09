"""The authorization probe catalogue (multi-dimensional).

Probes are declarative so the suite can report coverage and metrics sliced by
route and by caller role. Each probe is either:

  * forbidden  - a caller attempts something it must NOT be allowed to do
                 (tagged with the seeded flaw + OWASP category it targets), or
  * legitimate - a caller does something it SHOULD be allowed to do.

`action_allowed(resp)` returns True iff the attempted effect actually happened
(the forbidden data leaked / the privileged change took effect / the valid action
succeeded). On a correct API, forbidden probes are blocked and legitimate probes
succeed. Each probe runs against its own fresh client, so state-changing probes
stay isolated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

# username -> (role, tenant), mirroring sample_api/data.py
ROLE: Dict[str, tuple] = {
    "alice": ("user", "acme"),
    "bob": ("user", "acme"),
    "carol": ("user", "globex"),
    "mallory": ("manager", "globex"),
    "admin": ("admin", "acme"),
}

SEEDED_FLAWS = {
    "SF-01": "API1 BOLA - cross-user profile read (ssn/salary)",
    "SF-02": "API1 BOLA - cross-user order listing",
    "SF-03": "API3 BOPLA - mass assignment of role",
    "SF-04": "API3 BOPLA - mass assignment of tenant",
    "SF-05": "API1 BOLA - cross-tenant document read",
    "SF-06": "API5 BFLA - non-admin admin-only delete",
    "SF-07": "API5 BFLA - non-admin admin-only metrics",
    "SF-08": "API5 BFLA - manager delete outside tenant",
}


@dataclass
class Probe:
    probe_id: str
    kind: str                       # "forbidden" | "legitimate"
    seeded_flaw: Optional[str]
    owasp: str
    route: str                      # e.g. "GET /users/{id}" (for grouping)
    caller: str                     # username
    title: str
    method: str
    path: str
    body: Optional[dict]
    check: Callable                 # (resp) -> bool: did the attempted effect occur?

    @property
    def caller_role(self) -> str:
        return ROLE.get(self.caller, ("?", "?"))[0]


@dataclass
class ProbeResult:
    probe_id: str
    kind: str
    seeded_flaw: Optional[str]
    owasp: str
    route: str
    caller: str
    caller_role: str
    title: str
    action_allowed: bool
    status: int
    evidence: str


# --- response check helpers -------------------------------------------------

def _json(resp):
    try:
        return resp.json()
    except Exception:
        return None


def ok(resp) -> bool:
    return resp.status_code == 200


def leaks_field(field):
    def _c(resp):
        return resp.status_code == 200 and isinstance(_json(resp), dict) and field in _json(resp)
    return _c


def nonempty(resp) -> bool:
    j = _json(resp)
    return resp.status_code == 200 and isinstance(j, list) and len(j) > 0


def field_equals(field, value):
    def _c(resp):
        j = _json(resp)
        return resp.status_code == 200 and isinstance(j, dict) and j.get(field) == value
    return _c


# --- the probes -------------------------------------------------------------

PROBES: List[Probe] = [
    # ---- forbidden: BOLA (object level) ----
    Probe("F-BOLA-01", "forbidden", "SF-01", "API1 BOLA", "GET /users/{id}", "bob",
          "Same-tenant cross-user profile read (ssn leak)", "GET", "/users/1", None,
          leaks_field("ssn")),
    Probe("F-BOLA-02", "forbidden", "SF-02", "API1 BOLA", "GET /users/{id}/orders", "bob",
          "Cross-user order listing", "GET", "/users/1/orders", None, nonempty),
    Probe("F-BOLA-03", "forbidden", "SF-01", "API1 BOLA", "GET /users/{id}", "carol",
          "Cross-tenant profile read (globex->acme)", "GET", "/users/1", None,
          leaks_field("ssn")),
    # ---- forbidden: BOPLA (property level / mass assignment) ----
    Probe("F-BOPLA-01", "forbidden", "SF-03", "API3 BOPLA", "PATCH /users/{id}", "bob",
          "Self-promotion via role property", "PATCH", "/users/2", {"role": "admin"},
          field_equals("role", "admin")),
    Probe("F-BOPLA-02", "forbidden", "SF-04", "API3 BOPLA", "PATCH /users/{id}", "bob",
          "Cross-tenant move via tenant property", "PATCH", "/users/2", {"tenant": "globex"},
          field_equals("tenant", "globex")),
    Probe("F-BOPLA-03", "forbidden", "SF-03", "API3 BOPLA", "PATCH /users/{id}", "bob",
          "Salary tampering via protected property", "PATCH", "/users/2", {"salary": 999999},
          field_equals("salary", 999999)),
    # ---- forbidden: tenant isolation (object level) ----
    Probe("F-TENANT-01", "forbidden", "SF-05", "API1 BOLA", "GET /tenants/{t}/documents", "carol",
          "Cross-tenant document read (globex->acme)", "GET", "/tenants/acme/documents", None,
          nonempty),
    # ---- forbidden: BFLA (function level) ----
    Probe("F-BFLA-01", "forbidden", "SF-06", "API5 BFLA", "DELETE /admin/users/{id}", "bob",
          "Non-admin invokes admin delete", "DELETE", "/admin/users/3", None, ok),
    Probe("F-BFLA-02", "forbidden", "SF-07", "API5 BFLA", "GET /admin/metrics", "bob",
          "Non-admin reads admin metrics", "GET", "/admin/metrics", None, ok),
    Probe("F-BFLA-03", "forbidden", "SF-08", "API5 BFLA", "DELETE /admin/users/{id}", "mallory",
          "Manager deletes a user OUTSIDE their tenant", "DELETE", "/admin/users/1", None, ok),

    # ---- legitimate: should be ALLOWED ----
    Probe("L-01", "legitimate", None, "usability", "GET /users/{id}", "alice",
          "User reads their own profile", "GET", "/users/1", None, ok),
    Probe("L-02", "legitimate", None, "usability", "GET /users/{id}/orders", "bob",
          "User lists their own orders", "GET", "/users/2/orders", None, ok),
    Probe("L-03", "legitimate", None, "usability", "PATCH /users/{id}", "bob",
          "User updates their own email", "PATCH", "/users/2", {"email": "bob+new@acme.example"},
          field_equals("email", "bob+new@acme.example")),
    Probe("L-04", "legitimate", None, "usability", "GET /admin/metrics", "admin",
          "Admin reads admin metrics", "GET", "/admin/metrics", None, ok),
    Probe("L-05", "legitimate", None, "usability", "DELETE /admin/users/{id}", "admin",
          "Admin deletes a user", "DELETE", "/admin/users/2", None, ok),
    Probe("L-06", "legitimate", None, "usability", "GET /tenants/{t}/documents", "carol",
          "User reads their OWN tenant's documents", "GET", "/tenants/globex/documents", None,
          nonempty),
    Probe("L-07", "legitimate", None, "usability", "GET /users/{id}", "mallory",
          "Manager reads a user in their own tenant", "GET", "/users/3", None, ok),
    Probe("L-08", "legitimate", None, "usability", "DELETE /admin/users/{id}", "mallory",
          "Manager deletes a user in their OWN tenant", "DELETE", "/admin/users/3", None, ok),
    Probe("L-09", "legitimate", None, "usability", "GET /users/{id}", "admin",
          "Admin reads any user's profile", "GET", "/users/1", None, ok),
]


def _auth(client, username: str) -> dict:
    r = client.post("/login", json={"username": username})
    return {"Authorization": "Bearer " + r.json()["token"]}


def run_probe(probe: Probe, client_factory: Callable) -> ProbeResult:
    client = client_factory()
    hdr = _auth(client, probe.caller)
    if probe.method == "GET":
        resp = client.get(probe.path, headers=hdr)
    elif probe.method == "DELETE":
        resp = client.delete(probe.path, headers=hdr)
    elif probe.method == "PATCH":
        resp = client.patch(probe.path, headers=hdr, json=probe.body or {})
    elif probe.method == "POST":
        resp = client.post(probe.path, headers=hdr, json=probe.body or {})
    else:
        raise ValueError(probe.method)
    allowed = bool(probe.check(resp))
    evidence = "%s %s as %s(%s) -> %d%s" % (
        probe.method, probe.path, probe.caller, probe.caller_role, resp.status_code,
        " [effect occurred]" if allowed else "")
    return ProbeResult(
        probe.probe_id, probe.kind, probe.seeded_flaw, probe.owasp, probe.route,
        probe.caller, probe.caller_role, probe.title, allowed, resp.status_code, evidence)


def run_probes(client_factory: Callable) -> List[ProbeResult]:
    return [run_probe(p, client_factory) for p in PROBES]
