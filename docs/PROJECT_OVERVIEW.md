AuthMatrix-Veritas project overview

AuthMatrix-Veritas checks whether an API lets people use data or actions they should not.

What it checks

The project runs the same sample requests against three APIs:

A sample API with access bugs.

A fixed sample API.

An API that blocks every request.

The test set has 5 users, 3 roles, and 2 groups of sample data. It includes requests that should work and requests that should be blocked. This helps show whether an API is both safe and usable.

Results

The test set has 19 requests: 10 that should be blocked and 9 that should work. The fixed API passed these checks. The results apply only to the sample APIs in this project.

Run it

```bash
docker compose up --build
```

Open http://127.0.0.1:8092. See the main README for local test commands and limits.
