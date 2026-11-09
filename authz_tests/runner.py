"""Run the probe suite against each app and score it, sliced by route and role.

Research question: do the tests catch authorization failures (forbidden actions
that succeed) while still allowing valid actions?

The app is scored as an access-control classifier where "the app blocked the
action" is the positive prediction and "the action should be blocked" (a
forbidden probe) is the positive label:

    TP = forbidden & blocked      FP = legitimate & blocked (false denial)
    FN = forbidden & allowed      TN = legitimate & allowed
    recall      = TP/(TP+FN)   did it stop the attacks?
    precision   = TP/(TP+FP)   were its blocks justified?
    specificity = TN/(TN+FP)   did it let legitimate use through?

Usage:
  python -m authz_tests.runner
  python -m authz_tests.runner --json
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from typing import Callable, Dict, List

from fastapi.testclient import TestClient

from authz_tests.catalog import PROBES, SEEDED_FLAWS, ProbeResult, run_probes
from sample_api import deny_all, secure, vulnerable


def _factory(build_app: Callable) -> Callable:
    return lambda: TestClient(build_app())


def _confusion(results: List[ProbeResult]) -> Dict:
    tp = fp = fn = tn = 0
    for r in results:
        if r.kind == "forbidden":
            tp += int(not r.action_allowed)
            fn += int(r.action_allowed)
        else:
            fp += int(not r.action_allowed)
            tn += int(r.action_allowed)
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else None
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": round(recall, 3),
        "precision": None if precision is None else round(precision, 3),
        "specificity": round(specificity, 3),
    }


def _slice(results: List[ProbeResult], keyfn) -> Dict[str, Dict]:
    groups: Dict[str, List[ProbeResult]] = defaultdict(list)
    for r in results:
        groups[keyfn(r)].append(r)
    return {k: _confusion(v) for k, v in sorted(groups.items())}


def score_app(name: str, build_app: Callable) -> Dict:
    results = run_probes(_factory(build_app))
    conf = _confusion(results)
    found = {r.seeded_flaw for r in results
             if r.kind == "forbidden" and r.action_allowed and r.seeded_flaw}
    missed = sorted(set(SEEDED_FLAWS) - found)
    secure_ok = conf["fn"] == 0 and conf["fp"] == 0
    return {
        "name": name,
        "results": results,
        "confusion": conf,
        "by_route": _slice(results, lambda r: r.route),
        "by_role": _slice(results, lambda r: r.caller_role),
        "flaws_found": sorted(found),
        "flaws_missed": missed,
        "flaw_recall": round(len(found) / len(SEEDED_FLAWS), 3),
        "secure": secure_ok,
    }


def coverage_matrix() -> List[Dict]:
    """Which (caller role, route, expectation) combinations the suite exercises."""
    seen = []
    for p in PROBES:
        seen.append({"route": p.route, "role": p.caller_role, "caller": p.caller,
                     "kind": p.kind, "probe_id": p.probe_id, "title": p.title})
    return seen


def evaluate() -> Dict:
    return {
        "vulnerable": score_app("vulnerable", vulnerable.build_app),
        "secure": score_app("secure", secure.build_app),
        "deny_all": score_app("deny_all (control)", deny_all.build_app),
        "coverage": coverage_matrix(),
    }


def _fmt_conf(c: Dict) -> str:
    prec = "n/a" if c["precision"] is None else "%.2f" % c["precision"]
    return "recall=%.2f precision=%s specificity=%.2f (tp=%d fp=%d fn=%d tn=%d)" % (
        c["recall"], prec, c["specificity"], c["tp"], c["fp"], c["fn"], c["tn"])


def _print(result: Dict) -> None:
    print("=" * 74)
    print("API Authorization Testing - results  (%d probes)" % len(PROBES))
    print("=" * 74)
    for key in ("vulnerable", "secure", "deny_all"):
        s = result[key]
        print("\n[%s]  %s" % (s["name"], _fmt_conf(s["confusion"])))
        print("  seeded flaws found: %d/%d   secure? %s" % (
            len(s["flaws_found"]), len(SEEDED_FLAWS), s["secure"]))
    print("\n--- secure app: metrics by route ---")
    for route, c in result["secure"]["by_route"].items():
        print("  %-32s %s" % (route, _fmt_conf(c)))
    print("--- secure app: metrics by caller role ---")
    for role, c in result["secure"]["by_role"].items():
        print("  %-10s %s" % (role, _fmt_conf(c)))
    print("\n--- coverage: %d (role, route) probe combinations ---" % len(result["coverage"]))
    print("=" * 74)
    v, s, d = result["vulnerable"], result["secure"], result["deny_all"]
    print("vulnerable: flaw recall %d/%d | secure: %s | deny_all: %s" % (
        len(v["flaws_found"]), len(SEEDED_FLAWS),
        "PASS" if s["secure"] else "FAIL",
        "correctly NOT secure" if not d["secure"] else "ERROR"))


def _to_json(result: Dict) -> Dict:
    out = {}
    for key in ("vulnerable", "secure", "deny_all"):
        s = dict(result[key])
        s["results"] = [r.__dict__ for r in s["results"]]
        out[key] = s
    out["coverage"] = result["coverage"]
    return out


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description="Score authorization probes across apps.")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    result = evaluate()
    print(json.dumps(_to_json(result), indent=2) if args.json else "", end="")
    if not args.json:
        _print(result)


if __name__ == "__main__":
    main()
