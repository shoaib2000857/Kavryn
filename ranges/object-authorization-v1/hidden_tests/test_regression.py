"""Verifier-only positive and authentication regressions."""

from app import app


def test_missing_or_unknown_identity_cannot_read_documents() -> None:
    client = app.test_client()

    assert client.get("/documents/doc-alice").status_code == 401
    assert (
        client.get(
            "/documents/doc-alice", headers={"Authorization": "Bearer unknown-token"}
        ).status_code
        == 401
    )


def test_owner_keeps_access_after_authorization_fix() -> None:
    response = app.test_client().get(
        "/documents/doc-alice", headers={"Authorization": "Bearer test-token-alice"}
    )

    assert response.status_code == 200
    assert response.json is not None
    assert response.json["owner"] == "alice"
