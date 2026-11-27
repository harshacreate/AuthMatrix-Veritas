# Command line report

AuthMatrix-Veritas runs its checks locally against three sample applications:

- `vulnerable` shows the seeded access-control flaws.
- `secure` shows the expected fixed behaviour.
- `deny_all` is a control that blocks every request, including allowed use.

Run the human-readable report with:

```bash
python3 -m authz_tests.runner
```

The report prints overall recall, precision, specificity, and confusion counts,
then breaks the secure result down by route and caller role.

Use JSON output for scripts or a saved record:

```bash
python3 -m authz_tests.runner --json > report.json
```

The JSON contains the same three application scores plus the probe coverage
matrix. It includes the individual probe results, so a failing result can be
traced to a route, caller role, and seeded flaw.

The values describe the fixed local fixtures. They are not measurements of a
production API and should not be presented as production security rates.
