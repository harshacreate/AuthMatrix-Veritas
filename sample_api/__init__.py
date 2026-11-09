"""A deliberately-seeded sample API and its hardened counterpart.

Two apps are built from the same data layer:
  * vulnerable.py - contains seeded authorization flaws (for the tests to find)
  * secure.py     - the fixed version (the tests should find nothing)

Both are ordinary in-process ASGI apps; the test framework drives them with
Starlette's TestClient, so no network listener is opened.
"""
