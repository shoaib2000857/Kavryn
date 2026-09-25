"""A fixed, reviewed reverse proxy standing in front of the vulnerable
fixture -- the reversible-containment enforcement point for Change 7.

Takes no untrusted string arguments and executes no external command;
it only forwards HTTP requests and consults a rules file
(docs/TOOLS_AND_SANDBOXES.md: a reviewed fixed script is the one
allowed exception to "avoid shell expansion"). ``deny_query_patterns``
is applied as a set of regular expressions against the raw request
path+query; this is the "proxy rule" reversible-containment primitive
chosen in docs/DECISIONS.md ADR-029 (an engineering question
docs/OPEN_QUESTIONS.md left open for experimentation, not an owner
decision).

Every handled request is logged as one JSON line to stdout -- this is
the raw telemetry ``aegis.telemetry`` normalizes.
"""

from __future__ import annotations

import json
import os
import re
import socketserver
import sys
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler

BACKEND_URL = os.environ["AEGIS_BACKEND_URL"]
RULES_PATH = os.environ.get("AEGIS_RULES_PATH", "/rules/rules.json")
LISTEN_PORT = int(os.environ.get("AEGIS_PROXY_PORT", "8081"))

_HOP_BY_HOP_HEADERS = {"transfer-encoding", "connection", "keep-alive"}


def _load_rules() -> dict[str, list[str]]:
    try:
        with open(RULES_PATH) as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {"deny_query_patterns": []}
    if not isinstance(data, dict) or not isinstance(data.get("deny_query_patterns"), list):
        return {"deny_query_patterns": []}
    return data


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._handle()

    def _handle(self) -> None:
        rules = _load_rules()
        patterns = rules.get("deny_query_patterns", [])
        blocked = any(re.search(pattern, self.path) for pattern in patterns)
        log_entry: dict[str, object] = {
            "ts": time.time(),
            "method": "GET",
            "path": self.path,
            "client": self.client_address[0],
            "blocked": blocked,
        }

        if blocked:
            log_entry["status"] = 403
            body = b"blocked by containment rule"
            self.send_response(403)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            print(json.dumps(log_entry), flush=True)
            return

        try:
            with urllib.request.urlopen(BACKEND_URL + self.path, timeout=5) as response:
                body = response.read()
                status = response.status
                headers = response.getheaders()
        except urllib.error.HTTPError as exc:
            body = exc.read() or b""
            status = exc.code
            headers = list(exc.headers.items()) if exc.headers else []
        except urllib.error.URLError:
            log_entry["status"] = 502
            print(json.dumps(log_entry), flush=True)
            self.send_response(502)
            self.end_headers()
            return

        log_entry["status"] = status
        self.send_response(status)
        for key, value in headers:
            if key.lower() not in _HOP_BY_HOP_HEADERS:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)
        print(json.dumps(log_entry), flush=True)

    def log_message(self, format: str, *args: object) -> None:
        pass  # structured JSON logging above replaces the default stderr log


if __name__ == "__main__":
    with socketserver.ThreadingTCPServer(("0.0.0.0", LISTEN_PORT), ProxyHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            sys.exit(0)
