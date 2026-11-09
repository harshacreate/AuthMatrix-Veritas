"""The workbench web server (Flask).

Serves a single-page UI and small JSON APIs. The APIs drive the vulnerable and
secure sample APIs in-process (no network listener for them). Bind to loopback.

Run:
  python -m workbench.app            # http://127.0.0.1:8070
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, request, send_from_directory

from authz_tests.runner import evaluate
from workbench.engine import catalogue, run_request

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/health")
def health():
    return "ok"


@app.route("/api/catalogue")
def api_catalogue():
    return jsonify(catalogue())


@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.get_json(force=True, silent=True) or {}
    user = data.get("user") or None
    method = (data.get("method") or "GET").upper()
    path = data.get("path") or "/"
    body = data.get("body")
    if isinstance(body, str) and body.strip():
        import json
        try:
            body = json.loads(body)
        except Exception:
            return jsonify({"error": "body is not valid JSON"}), 400
    return jsonify(run_request(user, method, path, body))


@app.route("/api/metrics")
def api_metrics():
    full = evaluate()
    out = {}
    for key in ("vulnerable", "secure", "deny_all"):
        s = full[key]
        out[key] = {
            "name": s["name"],
            "confusion": s["confusion"],
            "by_route": s["by_route"],
            "by_role": s["by_role"],
            "flaws_found": s["flaws_found"],
            "flaws_missed": s["flaws_missed"],
            "flaw_recall": s["flaw_recall"],
            "secure": s["secure"],
            "results": [r.__dict__ for r in s["results"]],
        }
    out["coverage"] = full["coverage"]
    return jsonify(out)


def main():
    import os
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8070")), debug=False)


if __name__ == "__main__":
    main()
