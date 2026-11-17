# AuthMatrix-Veritas — Project Overview

**Multi-Tenant API Authorization Workbench**
Project overview

## Project summary

AuthMatrix-Veritas is a framework and interactive workbench for finding **broken
authorization** in a REST API — the class of bug where one user can reach another
user's data or call functions they shouldn't. It ships a deliberately-flawed
sample API, a hardened copy, and an over-restrictive deny-all control, then scores
a suite of probes against each. Flaws are drawn from the OWASP API Security Top 10
(2023): BOLA (API1), BOPLA / mass assignment (API3) and BFLA (API5).

## Main features

- **Request workbench (web UI):** choose a caller (user / role / tenant), an
  endpoint, an object id and a payload, then run it against the **vulnerable** and
  **hardened** APIs side by side — with the governing policy shown.
- **Multi-dimensional model:** 5 users across 3 roles (user / manager / admin) and
  2 tenants, with profiles (sensitive ssn/salary), orders and tenant documents.
- **Honest metrics:** recall, precision and specificity, sliced **by route and by
  role**, plus a coverage matrix of which combinations are tested.
- **Deny-all control:** proves the metric isn't fooled — blocking everything scores
  perfect recall but fails on precision/specificity.
- **Load a probe:** pick any seeded BOLA/BOPLA/BFLA case from a dropdown.

## Run with Docker

```sh
docker compose up --build -d      # then open http://localhost:8092
docker compose ps
docker compose down
```

The workbench drives both APIs in-process (no network listener for them) and binds
to `127.0.0.1` only, as a non-root user with a read-only root filesystem.

## What "secure" means here

An API is judged secure only if it **stops every attack AND denies no legitimate
request** (false negatives = 0 and false positives = 0).
