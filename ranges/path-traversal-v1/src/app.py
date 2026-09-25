"""An intentionally vulnerable file-download service (CWE-22).

See README.md. This file must never be "fixed" in place — it is the
fixed vulnerable baseline Aegis's repair loop generates candidate
patches against in a disposable workspace copy.
"""

from __future__ import annotations

import os

from flask import Flask, abort, request, send_file

app = Flask(__name__)
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.get("/download")
def download() -> object:
    filename = request.args.get("filename", "")
    # VULNERABLE: no path sanitization. A filename like
    # "../../../../etc/passwd" escapes BASE_DIR entirely.
    path = os.path.join(BASE_DIR, filename)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


@app.get("/healthz")
def healthz() -> object:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
