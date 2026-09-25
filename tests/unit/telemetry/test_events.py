from __future__ import annotations

import json
import time

import pytest

from aegis.evidence.store import InMemoryArtifactStore
from aegis.telemetry.events import (
    EventClassification,
    TelemetryParseError,
    classify_path,
    parse_proxy_log_line,
)


@pytest.mark.parametrize(
    "path",
    [
        "/download?filename=../secret.txt",
        "/download?filename=..%2fsecret.txt",
        "/download?filename=%2e%2e/secret.txt",
    ],
)
def test_classify_path_flags_traversal_indicators(path: str) -> None:
    assert classify_path(path) is EventClassification.SUSPICIOUS


def test_classify_path_benign_download() -> None:
    assert classify_path("/download?filename=welcome.txt") is EventClassification.BENIGN


def _log_line(**overrides: object) -> str:
    entry: dict[str, object] = {
        "ts": time.time(),
        "method": "GET",
        "path": "/download?filename=welcome.txt",
        "client": "172.18.0.1",
        "blocked": False,
        "status": 200,
    }
    entry.update(overrides)
    return json.dumps(entry)


def test_parses_a_valid_log_line() -> None:
    store = InMemoryArtifactStore()
    event = parse_proxy_log_line(_log_line(), case_id="AGE-0001", event_id="evt-1", artifacts=store)
    assert event.status_code == 200
    assert event.inferred_classification is EventClassification.BENIGN
    assert store.get(event.raw_digest) is not None


def test_parses_a_blocked_attack_line() -> None:
    store = InMemoryArtifactStore()
    event = parse_proxy_log_line(
        _log_line(path="/download?filename=../secret.txt", blocked=True, status=403),
        case_id="AGE-0001",
        event_id="evt-2",
        artifacts=store,
    )
    assert event.blocked is True
    assert event.inferred_classification is EventClassification.SUSPICIOUS


def test_non_json_line_raises() -> None:
    with pytest.raises(TelemetryParseError):
        parse_proxy_log_line(
            "not json", case_id="AGE-0001", event_id="evt-3", artifacts=InMemoryArtifactStore()
        )


def test_missing_required_field_raises() -> None:
    with pytest.raises(TelemetryParseError, match="missing required field"):
        parse_proxy_log_line(
            json.dumps({"method": "GET"}),
            case_id="AGE-0001",
            event_id="evt-4",
            artifacts=InMemoryArtifactStore(),
        )


def test_invalid_timestamp_raises() -> None:
    with pytest.raises(TelemetryParseError, match="invalid timestamp"):
        parse_proxy_log_line(
            _log_line(ts="not-a-number"),
            case_id="AGE-0001",
            event_id="evt-5",
            artifacts=InMemoryArtifactStore(),
        )
