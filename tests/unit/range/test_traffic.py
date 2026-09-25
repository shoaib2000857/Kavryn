from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aegis.range.traffic import send_get


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/ok":
            body = b"hello"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def local_server() -> Iterator[str]:
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_send_get_returns_status_and_body_length(local_server: str) -> None:
    outcome = send_get(local_server, "/ok")
    assert outcome.status_code == 200
    assert outcome.body_length == len(b"hello")
    assert outcome.elapsed_seconds >= 0


def test_send_get_captures_http_error_status(local_server: str) -> None:
    outcome = send_get(local_server, "/missing")
    assert outcome.status_code == 404


def test_send_get_reports_connection_failure_as_status_zero_not_an_exception() -> None:
    """A container not yet listening (or already stopped) must be data a
    caller can retry on, not an exception that breaks a readiness loop."""
    with HTTPServer(("127.0.0.1", 0), _Handler) as probe:
        unused_port = probe.server_port
    outcome = send_get(f"http://127.0.0.1:{unused_port}", "/ok", timeout=1.0)
    assert outcome.status_code == 0
