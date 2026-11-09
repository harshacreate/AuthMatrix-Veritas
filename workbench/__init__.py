"""Interactive authorization workbench.

A small Flask app that runs an arbitrary request against BOTH the vulnerable and
the hardened API in-process, and shows the request, each response, the verdict,
and the relevant policy side by side -- plus live metrics and a coverage matrix.
"""
