# API access test report

## Question

Can a test set find sample API access bugs and also check that normal requests still work?

## Method

The project runs the same sample routes against three APIs: one with planted access bugs, one with fixes, and one that blocks every request.

The test set has 5 users, 3 roles, and 2 groups of sample data. It checks 19 requests: 10 that should be blocked and 9 that should work.

The project reports three scores:

- Recall: how many forbidden requests were blocked.
- Precision: how many blocked requests really should have been blocked.
- Specificity: how many normal requests were allowed.

## Results

| API | Recall | Precision | Specificity |
|---|---:|---:|---:|
| API with bugs | 0.00 | n/a | 1.00 |
| Fixed API | 1.00 | 1.00 | 1.00 |
| Blocks every request | 1.00 | 0.53 | 0.00 |

The fixed API passed the sample checks. The API that blocks every request also stopped all forbidden requests, but it stopped normal requests too. It is not safe to use just because it blocks everything.

## Limits

These are small sample APIs and sample data. The results do not show how the tests would work on a real service. The sample token is simple because the project is about access rules, not login security.

## Run the checks

```bash
make setup
make test
make run
make workbench
```

The workbench runs at http://127.0.0.1:8070.
