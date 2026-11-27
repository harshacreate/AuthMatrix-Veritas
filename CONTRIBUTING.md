# Contributing

Thanks for helping improve AuthMatrix-Veritas.

## Setup

Use Python 3.10 or newer and install the development dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Run the checks

Run the full test suite before opening a pull request:

```bash
python3 -m pytest -q
```

To print the authorization report:

```python
python3 -m authz_tests.runner
```

Use `--json` when another tool needs structured output:

```bash
python3 -m authz_tests.runner --json
```

The sample APIs use local, fixed data. Do not send real credentials or production
requests to them.

## Pull requests

Keep each pull request focused. Explain what changed and include the command
used to validate it. Changes to the vulnerable sample should keep its marked
flaws intact; update the secure sample and tests when changing the expected
authorization behaviour.
