"""Intentionally vulnerable synthetic document service (CWE-862/CWE-639).

This fixture models an authenticated principal supplied by a trusted test
middleware and a document lookup that omits the owner authorization check.
It is for local, isolated Aegis evaluation only.
"""

from __future__ import annotations

from flask import Flask, abort, g, jsonify, request

app = Flask(__name__)

# Synthetic identities for this owned range only; this is not authentication
# suitable for deployment. Tests bind these fixture tokens to fixed principals.
_TEST_TOKENS = {"test-token-alice": "alice", "test-token-bob": "bob"}
_DOCUMENTS = {
    "doc-alice": {"owner": "alice", "body": "Alice's private synthetic note."},
    "doc-bob": {"owner": "bob", "body": "Bob's private synthetic note."},
}


@app.before_request
def bind_test_principal() -> None:
    if request.path == "/healthz":
        return
    token = request.headers.get("Authorization", "")
    if not token.startswith("Bearer "):
        abort(401)
    principal = _TEST_TOKENS.get(token.removeprefix("Bearer "))
    if principal is None:
        abort(401)
    g.principal = principal


@app.get("/documents/<document_id>")
def get_document(document_id: str) -> object:
    document = _DOCUMENTS.get(document_id)
    if document is None:
        abort(404)
    # VULNERABLE: the authenticated principal is never compared with document["owner"].
    return jsonify({"id": document_id, "owner": document["owner"], "body": document["body"]})


@app.get("/healthz")
def healthz() -> object:
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
