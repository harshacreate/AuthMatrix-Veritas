"""Interactive authorization workbench.

A small Flask app that runs an arbitrary request against BOTH the vulnerable and
the hardened API in-process, and shows the request, each response, the verdict,
and its policy side by side, with live scores and a coverage matrix.
"""
