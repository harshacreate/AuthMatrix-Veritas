# API Authorization Testing — Project Report

## Research question

Can a declarative test suite reliably **catch broken-authorization failures**
(forbidden actions that succeed) in a REST API **while still allowing valid
actions** — and can that be measured, not just demonstrated?

Authorization bugs dominate real-world API risk: the OWASP API Security Top 10
(2023) lists BOLA (API1), BOPLA / mass assignment (API3) and BFLA (API5) among
the most severe. This project tests for all three.

## Method

- **Three targets, same routes.** A deliberately-flawed API (`sample_api/vulnerable.py`),
  a hardened copy (`sample_api/secure.py`), and an over-restrictive deny-all control
  (`sample_api/deny_all.py`).
- **Multi-dimensional model.** 5 users across 3 roles (user / manager / admin) and
  2 tenants (acme / globex), with user profiles (sensitive `ssn`/`salary`), orders,
  and tenant documents. This exposes authorization across users, roles, tenants,
  resources and object properties.
- **Declarative probes** (`authz_tests/catalog.py`): each probe is *forbidden*
  (must be blocked) or *legitimate* (must succeed), tagged with the seeded flaw,
  OWASP category, route and caller role. A probe's `action_allowed(resp)` returns
  whether the attempted effect actually occurred (data leaked / privileged change
  applied / valid action succeeded).
- **Classifier scoring** (`authz_tests/runner.py`): treating "the app blocked the
  action" as the positive prediction and "should be blocked" as the positive label:
  recall (attacks stopped), precision (blocks justified), specificity (valid use
  allowed) — reported overall and **sliced by route and by role**.
- **Interactive workbench** (`workbench/`): a Flask UI to run any request against
  the vulnerable and hardened APIs side by side, with the governing policy shown.

## Results (synthetic sample APIs)

19 probes — 10 forbidden, 9 legitimate.

| Target | recall | precision | specificity | verdict |
|--------|--------|-----------|-------------|---------|
| vulnerable | 0.00 | n/a | 1.00 | finds **8/8** seeded flaws (it allows every forbidden action) |
| **hardened** | **1.00** | **1.00** | **1.00** | **PASS** — stops every attack, breaks no valid action |
| deny-all (control) | 1.00 | 0.53 | 0.00 | correctly **NOT** secure (blocks legitimate use too) |

Per-route and per-role: the hardened API scores perfectly (fn = fp = 0) on all six
routes and for all three roles, including the subtle tenant-scoped cases — a
manager may delete a user **inside** their tenant (allowed) but not **outside** it
(blocked).

The deny-all control is the key honesty check: it blocks every attack (recall 1.0)
yet is correctly judged insecure because it also denies legitimate requests
(precision 0.53, specificity 0.0). A "block everything" API cannot score well here.

## Limitations

- The APIs and data are **synthetic** and small; results demonstrate the test
  methodology and the fix, not performance against a production API.
- The token scheme is trivial (base64 username) on purpose — the focus is
  *authorization*, not authentication cryptography.
- Coverage is the probes listed in the coverage matrix; it is not exhaustive over
  all (user × resource × action) combinations.

## Reproduce

```bash
make setup
make test        # 9 tests (full recall, zero false positives, route/role perfect)
make run         # printed report with route/role metrics + coverage
make workbench   # interactive UI at http://127.0.0.1:8070
```

Results are deterministic (fixed seed data), so another reviewer gets identical
numbers.
