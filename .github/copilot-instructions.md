# GitHub Copilot instructions

## Project scope
AuthMatrix-Veritas compares authorization behavior in intentionally vulnerable, hardened, and deny-all sample APIs. Keep all exercises local and use only the repository's fictional fixtures.

## Before changing code
- Read the relevant README, security notes, implementation, and tests first.
- Preserve the three API variants and the distinction between forbidden requests and valid requests.
- Do not add real service endpoints, credentials, personal data, or network calls.

## Implementation and validation
- Add or update tests for both allowed and forbidden access, including role and resource boundaries.
- Keep the intentionally vulnerable implementation isolated as a teaching fixture; do not weaken the hardened API to make a test pass.
- Use the documented local commands: `python -m pytest -q` / `make test` and `make run`.
- Keep result claims limited to the sample routes and test cases. State when an example is illustrative rather than evidence about a production API.
