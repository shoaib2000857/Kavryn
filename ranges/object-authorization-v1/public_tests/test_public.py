"""Visible intended-behavior checks for the synthetic authorization fixture."""

from app import app


def test_owner_can_read_own_document() -> None:
    response = app.test_client().get(
        "/documents/doc-alice", headers={"Authorization": "Bearer test-token-alice"}
    )

    assert response.status_code == 200
    assert response.json is not None
    assert response.json["owner"] == "alice"
    assert response.json["body"] == "Alice's private synthetic note."


def test_unknown_document_is_not_found() -> None:
    response = app.test_client().get(
        "/documents/does-not-exist", headers={"Authorization": "Bearer test-token-alice"}
    )

    assert response.status_code == 404
