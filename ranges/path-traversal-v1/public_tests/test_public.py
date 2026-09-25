"""Public tests: legitimate-behavior checks visible to whatever generates a patch.

Run with the (patched) source tree on PYTHONPATH, e.g.:
    PYTHONPATH=ranges/path-traversal-v1/src pytest ranges/path-traversal-v1/public_tests
"""

from __future__ import annotations

import pytest
from app import app as flask_app
from flask.testing import FlaskClient


@pytest.fixture
def client() -> FlaskClient:
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


def test_healthz_ok(client: FlaskClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200


def test_download_of_an_allowed_file_works(client: FlaskClient) -> None:
    response = client.get("/download?filename=welcome.txt")
    assert response.status_code == 200
    assert b"Welcome to demo-api" in response.data


def test_download_of_a_missing_file_is_a_clean_404(client: FlaskClient) -> None:
    response = client.get("/download?filename=does-not-exist.txt")
    assert response.status_code == 404
