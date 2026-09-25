"""Benign-client and attack-controller HTTP request helpers.

Both the "benign client" and "attack controller" described in
docs/IMPLEMENTATION_HANDOFF.md Change 7 are the same primitive: send
one GET request and record what happened. What makes a request
"benign" or an "attack" is the caller's choice of path/query, not a
different code path -- there is exactly one way requests reach the
range, matching docs/THREAT_MODEL.md's rule that the evaluation
controller, not the agent, starts and stops replays.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request

from aegis.domain.base import AegisModel

__all__ = ["RequestOutcome", "send_get"]


class RequestOutcome(AegisModel):
    """``status_code=0`` means the request never reached a server that
    returned a real HTTP status (connection refused/reset, DNS failure,
    timeout) -- not a valid status, but data a caller can retry on
    rather than an exception to handle, mirroring
    ``ContainerRunResult``'s "a completed call does not imply success"
    treatment of infrastructure conditions.
    """

    status_code: int
    elapsed_seconds: float
    body_length: int


def send_get(base_url: str, path: str, *, timeout: float = 5.0) -> RequestOutcome:
    started = time.monotonic()
    try:
        with urllib.request.urlopen(base_url + path, timeout=timeout) as response:
            body = response.read()
            return RequestOutcome(
                status_code=response.status,
                elapsed_seconds=time.monotonic() - started,
                body_length=len(body),
            )
    except urllib.error.HTTPError as exc:
        body = exc.read() or b""
        return RequestOutcome(
            status_code=exc.code, elapsed_seconds=time.monotonic() - started, body_length=len(body)
        )
    except OSError:
        # urllib.error.URLError is itself an OSError subclass, and a
        # reset/refused connection can also surface as a raw OSError
        # (e.g. ConnectionResetError) before any HTTP status is read --
        # both mean "never reached a server," not "server said no."
        return RequestOutcome(
            status_code=0, elapsed_seconds=time.monotonic() - started, body_length=0
        )
