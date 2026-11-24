AuthMatrix-Veritas

AuthMatrix-Veritas tests whether an API lets users access data or actions they should not. It checks a vulnerable sample API, a fixed version, and a version that blocks every request.

![CI](https://github.com/harshacreate/AuthMatrix-Veritas/actions/workflows/ci.yml/badge.svg)

How it works

The same sample routes are tested in all three APIs. The test set includes requests that should be blocked and requests that should work.

The project reports:

Recall: how many forbidden requests were blocked.

Precision: how many blocked requests really should have been blocked.

Specificity: how many allowed requests were allowed.

This matters because an API that blocks every request would stop attacks but would also stop normal use.

Results

The project checks 19 sample requests: 10 forbidden and 9 allowed.

API: Vulnerable sample; Recall: 0.00; Precision: n/a; Specificity: 1.00

API: Fixed sample; Recall: 1.00; Precision: 1.00; Specificity: 1.00

API: Blocks everything; Recall: 1.00; Precision: 0.53; Specificity: 0.00

These results apply only to the sample APIs and tests in this repository.

Run it

With Docker:

```bash
docker compose up --build
```

Open http://127.0.0.1:8092.

For local tests:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
make test
make run
```

The optional workbench runs at http://127.0.0.1:8070. Keep the vulnerable sample on your own computer and use only the test data here.

Project files

[Project overview](docs/PROJECT_OVERVIEW.md)

[Learning guide](docs/LEARNING_GUIDE.md)

[Walkthrough](docs/PROJECT_WALKTHROUGH.md)

[Project report](docs/REPORT.md)

This project uses small sample APIs and does not test a live service.
