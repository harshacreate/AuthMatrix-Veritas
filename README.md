# AuthMatrix-Veritas — Multi-Tenant API Authorization Workbench

## Run with Docker

```bash
docker compose up --build -d      # then open http://localhost:8092
docker compose down               # stop
```

This repository is standalone; the commands below build and run this project on its own.

A test framework that hunts for **broken authorization** in a REST API — the
class of bug where one user can reach another user's data or call functions they
shouldn't. It ships with a deliberately-flawed sample API, a hardened copy of the
same API, and a deny-everything control, then scores two kinds of probe against
each:

- **forbidden** probes — a low-privilege caller attempts something it must not be
  allowed to do (these target the seeded flaws);
- **legitimate** probes — a caller does something it *should* be allowed to do
  (read its own data, an admin using an admin route).

The flaws are drawn from the
[OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/):
BOLA (API1), BOPLA / mass assignment (API3), and BFLA (API5).

The sample APIs are **multi-dimensional**: 5 users across 3 roles
(user / manager / admin) and 2 tenants, with profiles (sensitive `ssn`/`salary`),
orders and tenant documents — so authorization is tested across users, roles,
tenants, resources and object properties. There is also an **interactive web
workbench** to run requests against the vulnerable and hardened APIs side by side.
See [REPORT.md](REPORT.md) for the research question, method, results and limits.

## Why both kinds of probe matter

If you only test forbidden actions, an API that **denies every request** blocks
all the attacks and looks perfect — but it's useless, because it also breaks all
legitimate use. Scoring only the "did it reject the attacks?" rate measures
*specificity*, not security.

So the app is scored as an access-control classifier over *both* probe sets,
treating "the app blocked the action" as the positive prediction and "the action
should be blocked" (a forbidden probe) as the positive label:

```
TP = forbidden & blocked      FP = legitimate & blocked (false denial)
FN = forbidden & allowed      TN = legitimate & allowed
recall      = TP / (TP + FN)   did it stop the attacks?
precision   = TP / (TP + FP)   were its blocks justified?
specificity = TN / (TN + FP)   did it let legitimate use through?
```

An app is judged **secure only if it stops every attack AND denies no legitimate
request** (FN = 0 and FP = 0). The bundled `deny_all` control proves the point:
it has recall 1.0 but precision 0.5 and specificity 0.0, so it is correctly *not*
judged secure.

## Seeded flaws

| ID | OWASP | Endpoint | Flaw |
|----|-------|----------|------|
| SF-01 | API1 BOLA | `GET /users/{id}` | returns any user's record (incl. ssn/salary), cross-user and cross-tenant |
| SF-02 | API1 BOLA | `GET /users/{id}/orders` | lists any user's orders |
| SF-03 | API3 BOPLA | `PATCH /users/{id}` | client-set `role` → self-promotion |
| SF-04 | API3 BOPLA | `PATCH /users/{id}` | client-set `tenant` → cross-tenant move |
| SF-05 | API1 BOLA | `GET /tenants/{t}/documents` | cross-tenant document read (tenant isolation) |
| SF-06 | API5 BFLA | `DELETE /admin/users/{id}` | admin function, no role check |
| SF-07 | API5 BFLA | `GET /admin/metrics` | admin data, no role check |
| SF-08 | API5 BFLA | `DELETE /admin/users/{id}` | manager deletes a user outside their tenant |

Each is marked `SEEDED FLAW <id>` in [sample_api/vulnerable.py](sample_api/vulnerable.py)
and fixed with a matching `FIX <id>` in [sample_api/secure.py](sample_api/secure.py).

## Layout

```
sample_api/
  data.py         users (roles + tenants), orders, documents + a trivial token
  vulnerable.py   the seeded API
  secure.py       the hardened API (object/property/function-level checks)
  deny_all.py     the over-restrictive control (denies everything)
authz_tests/
  catalog.py      declarative probes, tagged with seeded flaw, route and role
  runner.py       scores recall/precision/specificity, sliced by route and role
  policies.py     human-readable policy per route (shown in the workbench)
workbench/
  engine.py       runs a request against both APIs in-process
  app.py          Flask server + JSON APIs
  static/         the single-page UI
tests/            pytest assertions over the scoring and the workbench engine
```

## Quick start

```bash
make setup      # fastapi, uvicorn, httpx, flask, pytest
make run        # probe report with metrics sliced by route and role
make workbench  # interactive web UI at http://127.0.0.1:8070
make test       # pytest assertions
```

### Interactive workbench

`make workbench` serves a single page (loopback only) where you pick a caller
(user/role/tenant), an endpoint, an object id and a payload, then run it against
**both** APIs at once. You see each request/response, an ALLOWED/BLOCKED verdict,
the governing authorization policy, and live metrics (recall/precision/specificity
by route and role) plus the coverage matrix. Load a seeded probe from the dropdown
to reproduce a specific BOLA/BOPLA/BFLA case.

Abbreviated `make run` output:

```
[secure]
  block  F-BOLA-01  forbidden   GET /users/1 as bob -> 403
  allow  L-01       legitimate  GET /users/1 as alice -> 200
  ...
  forbidden blocked (recall)      : 5/5
  legitimate allowed (specificity): 5/5
  precision (blocks justified)    : 1.00

secure app:   recall=1.0 precision=1.0 specificity=1.0 -> PASS
deny_all app: recall=1.0 precision=0.5 specificity=0.0 -> correctly NOT secure
```

## Running the APIs standalone

```bash
make serve-vuln     # http://127.0.0.1:8000/docs
make serve-secure   # http://127.0.0.1:8001/docs
```

Both bind to loopback only. You can then drive the probes, `curl`, or any API
client against them manually.

## Extending it

- **Add an endpoint + flaw:** implement it in `vulnerable.py` with a
  `SEEDED FLAW <id>` comment, fix it in `secure.py`, register the id in
  `SEEDED_FLAWS`.
- **Add a probe:** write a function in `authz_tests/catalog.py` returning a
  `ProbeResult`. Mark it `kind="forbidden"` (tagged with a seeded-flaw id) or
  `kind="legitimate"`, and add it to `FORBIDDEN_PROBES` or `LEGIT_PROBES`. Each
  probe builds its own fresh client, so state-changing probes stay isolated.

## Scope & safety

The framework only ever drives its own bundled sample API, in-process via
Starlette's `TestClient`. It performs no scanning of third-party systems.
