Learning guide

This guide explains the main ideas in AuthMatrix-Veritas.

Login and access rules

Login checks who a person is. Access rules check what that person is allowed to do. An API can get login right and still let a user read someone else's data.

Common API access bugs

- BOLA means a user can reach another user's record, often by changing an ID in a link.
- BFLA means a user can call an action that should be limited to another role.
- Mass assignment means a user can change a field they should not control, such as their role.

This project uses sample cases based on these bug types. The OWASP API Security list names these risks.

How the scores work

- Recall shows how many requests that should be blocked were blocked.
- Precision shows how many blocked requests really should have been blocked.
- Specificity shows how many requests that should work were allowed.

Testing only forbidden requests can make a system that blocks everything look good. That is why this project also tests normal requests.

Limits

The APIs and data are small local examples. Passing these tests does not prove that a real API is safe.
