Run and read the project

This guide shows how to start AuthMatrix-Veritas and read its results.

Start with Docker

```bash
docker compose up --build
```

Open http://127.0.0.1:8092.

Run it on your computer

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
make test
make run
```

To open the optional workbench, run `make workbench`. It uses http://127.0.0.1:8070.

Main files

- `sample_api/vulnerable.py` has the sample API with access bugs.
- `sample_api/secure.py` has the same routes with access checks.
- `sample_api/deny_all.py` blocks every protected request.
- `authz_tests/catalog.py` lists requests that should work or be blocked.
- `authz_tests/runner.py` runs the requests and prints the scores.
- `workbench/` contains the optional web page.

Read the results

The test set has 10 requests that should be blocked and 9 that should work.

The fixed API should block all 10 forbidden requests and allow all 9 normal requests. The deny-all API blocks attacks, but it also blocks normal use. This is why the project reports more than one score.

Safety and limits

The vulnerable API is for local practice only. It uses simple sample data and a sample token. Do not put it on a public server or use it with real data.
