"""Assertions over the expanded, multi-dimensional authorization suite."""

from authz_tests.catalog import PROBES, SEEDED_FLAWS
from authz_tests.runner import evaluate


def test_vulnerable_app_full_flaw_recall():
    v = evaluate()["vulnerable"]
    assert v["flaws_missed"] == [], "unexpected missed flaws: %s" % v["flaws_missed"]
    assert v["flaw_recall"] == 1.0


def test_secure_app_stops_attacks_and_allows_legit():
    s = evaluate()["secure"]
    c = s["confusion"]
    assert c["fn"] == 0 and c["fp"] == 0
    assert c["recall"] == 1.0 and c["precision"] == 1.0 and c["specificity"] == 1.0
    assert s["secure"] is True


def test_secure_app_perfect_for_every_route():
    by_route = evaluate()["secure"]["by_route"]
    assert len(by_route) >= 6
    for route, c in by_route.items():
        assert c["fn"] == 0 and c["fp"] == 0, "route %s imperfect: %s" % (route, c)


def test_deny_all_is_not_judged_secure():
    d = evaluate()["deny_all"]
    c = d["confusion"]
    assert c["recall"] == 1.0            # blocks all attacks ...
    assert c["fp"] > 0                    # ... but also blocks legitimate use
    assert c["specificity"] == 0.0
    assert c["precision"] is not None and c["precision"] < 1.0
    assert d["secure"] is False


def test_owasp_categories_represented():
    cats = {r.owasp.split(" ", 1)[0] for r in evaluate()["vulnerable"]["results"]
            if r.kind == "forbidden"}
    assert {"API1", "API3", "API5"} <= cats       # BOLA, BOPLA, BFLA


def test_suite_covers_multiple_roles_and_tenancy():
    roles = {p.caller_role for p in PROBES}
    assert {"user", "manager", "admin"} <= roles
    # a manager acting outside their tenant must be a forbidden probe (BFLA/tenant)
    assert any(p.caller == "mallory" and p.kind == "forbidden" for p in PROBES)
    # and a manager acting inside their tenant must be a legitimate probe
    assert any(p.caller == "mallory" and p.kind == "legitimate" for p in PROBES)


# --- workbench engine ---

def test_workbench_shows_fix_blocks_for_bola():
    from workbench.engine import run_request
    res = run_request("bob", "GET", "/users/1", None)   # bob reads alice
    assert res["vulnerable"]["allowed"] is True          # leaks on vulnerable
    assert res["secure"]["allowed"] is False             # blocked on hardened
    assert res["verdict"] == "fix_blocks"
    assert res["policy"]["owasp"].startswith("API1")


def test_workbench_legit_action_allowed_on_both():
    from workbench.engine import run_request
    res = run_request("bob", "PATCH", "/users/2", {"email": "b@acme.example"})
    assert res["vulnerable"]["allowed"] and res["secure"]["allowed"]
    assert res["verdict"] == "both_allow"


def test_workbench_catalogue_is_populated():
    from workbench.engine import catalogue
    cat = catalogue()
    assert len(cat["users"]) == 5
    assert len(cat["scenarios"]) == len(PROBES)
    assert len(SEEDED_FLAWS) == 8
