from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aegis.domain.audit import AuditEvent, AuditEventType
from aegis.domain.base import ActorRole, Digest
from aegis.evidence.audit import audit_event_digest
from aegis.evidence.audit_stream import (
    AuditStreamError,
    export_audit_jsonl,
    parse_audit_jsonl,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def _audit_events() -> tuple[AuditEvent, AuditEvent]:
    now = datetime(2026, 9, 25, tzinfo=UTC)
    first = AuditEvent(
        id="audit-0001",
        case_id="AGE-0001",
        created_at=now,
        event_type=AuditEventType.CASE_CREATED,
        actor_id="operator:test",
        role=ActorRole.OPERATOR,
        subject_ref="case://AGE-0001",
        summary="case created",
        integrity=Digest(digest="0" * 64),
    )
    first = first.model_copy(update={"integrity": audit_event_digest(first)})
    second = AuditEvent(
        id="audit-0002",
        case_id="AGE-0001",
        created_at=now + timedelta(seconds=1),
        event_type=AuditEventType.ACTION_REQUESTED,
        actor_id="reasoning_runtime:v1",
        role=ActorRole.REASONING_RUNTIME,
        subject_ref="action-request://AGE-0001/request-1",
        summary="scan requested",
        integrity=Digest(digest="0" * 64),
        prev_event_digest=first.integrity,
    )
    second = second.model_copy(update={"integrity": audit_event_digest(second)})
    return first, second


def test_jsonl_round_trip_is_stable_and_verifies() -> None:
    events = _audit_events()
    stream = export_audit_jsonl(events)
    assert stream == export_audit_jsonl(events)
    assert parse_audit_jsonl(stream) == events
    assert stream.endswith("\n")


def test_export_rejects_invalid_chain() -> None:
    events = _audit_events()
    tampered = events[0].model_copy(update={"summary": "rewritten"})
    with pytest.raises(AuditStreamError, match="invalid audit chain"):
        export_audit_jsonl((tampered, events[1]))


def test_export_rejects_empty_chain() -> None:
    with pytest.raises(AuditStreamError, match="empty"):
        export_audit_jsonl(())


def test_parse_rejects_modified_body_and_reordered_events() -> None:
    events = _audit_events()
    stream = export_audit_jsonl(events)
    lines = stream.splitlines()
    first = json.loads(lines[0])
    first["summary"] = "rewritten"
    with pytest.raises(AuditStreamError, match="verification failed"):
        parse_audit_jsonl(json.dumps(first) + "\n" + "\n".join(lines[1:]))
    if len(lines) > 1:
        with pytest.raises(AuditStreamError, match="verification failed"):
            parse_audit_jsonl("\n".join(reversed(lines)) + "\n")


def test_parse_rejects_blank_malformed_and_mixed_case_streams() -> None:
    events = _audit_events()
    valid = export_audit_jsonl(events)
    with pytest.raises(AuditStreamError, match="blank line"):
        parse_audit_jsonl(valid + "\n")
    with pytest.raises(AuditStreamError, match="invalid audit event"):
        parse_audit_jsonl("{not-json}\n")

    other = events[0].model_copy(update={"case_id": "AGE-0002"})
    with pytest.raises(AuditStreamError, match="exactly one case chain"):
        export_audit_jsonl((events[0], other))


def test_verification_cli_accepts_valid_stream_and_rejects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(export_audit_jsonl(_audit_events()), encoding="utf-8")
    script = REPO_ROOT / "scripts" / "verify_audit_stream.py"
    valid = subprocess.run(
        [sys.executable, str(script), str(path)], capture_output=True, text=True, timeout=10
    )
    assert valid.returncode == 0
    assert "verified 2 events for AGE-0001" in valid.stdout

    path.write_text(path.read_text(encoding="utf-8").replace("case created", "rewritten"))
    invalid = subprocess.run(
        [sys.executable, str(script), str(path)], capture_output=True, text=True, timeout=10
    )
    assert invalid.returncode == 2
    assert "verification failed" in invalid.stderr
