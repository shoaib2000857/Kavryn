"""Hidden regression tests: legitimate behavior must still work after patching.

A patch that blocks the exploit by breaking all downloads passes the
exploit-replay check but must fail here
(docs/EVIDENCE_AND_ASSURANCE.md hard failure: "patch that blocks the
exploit but breaks legitimate behavior").
"""

from __future__ import annotations

import pytest
from app import app as flask_app
from flask.testing import FlaskClient


@pytest.fixture
def client() -> FlaskClient:
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


def test_legitimate_download_still_works(client: FlaskClient) -> None:
    response = client.get("/download?filename=welcome.txt")
    assert response.status_code == 200
    assert b"Welcome to demo-api" in response.data


def test_healthz_still_works(client: FlaskClient) -> None:
    assert client.get("/healthz").status_code == 200
