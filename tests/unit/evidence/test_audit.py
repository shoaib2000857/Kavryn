from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest

from aegis.domain.audit import AuditEvent, AuditEventType
from aegis.domain.base import ActorRole, Digest
from aegis.evidence.audit import AuditChainError, InMemoryAuditSink


def _event(now: datetime, **overrides: Any) -> AuditEvent:
    defaults: dict[str, Any] = {
        "id": "audit-0001",
        "case_id": "AGE-0001",
        "created_at": now,
        "event_type": AuditEventType.CASE_CREATED,
        "actor_id": "operator:alice",
        "role": ActorRole.OPERATOR,
        "subject_ref": "case://AGE-0001",
        "summary": "case created",
        "integrity": Digest(digest="a" * 64),
        "prev_event_digest": None,
    }
    defaults.update(overrides)
    return AuditEvent(**defaults)


def test_first_event_appends_with_no_predecessor(now: datetime) -> None:
    sink = InMemoryAuditSink()
    event = _event(now)
    sink.append(event)
    assert sink.events_for_case("AGE-0001") == (event,)
    assert sink.last_event("AGE-0001") == event


def test_correctly_chained_second_event_appends(now: datetime) -> None:
    sink = InMemoryAuditSink()
    first = _event(now)
    sink.append(first)
    second = _event(
        now + timedelta(seconds=1),
        id="audit-0002",
        event_type=AuditEventType.ACTION_REQUESTED,
        subject_ref="action-request://AGE-0001/req-1",
        prev_event_digest=first.integrity,
        integrity=Digest(digest="b" * 64),
    )
    sink.append(second)
    assert sink.events_for_case("AGE-0001") == (first, second)


def test_first_event_with_a_predecessor_digest_is_rejected(now: datetime) -> None:
    sink = InMemoryAuditSink()
    event = _event(now, prev_event_digest=Digest(digest="c" * 64))
    with pytest.raises(AuditChainError):
        sink.append(event)


def test_second_event_with_wrong_prev_digest_is_rejected(now: datetime) -> None:
    """Simulates a forged or spliced audit event: the chain must reject it."""
    sink = InMemoryAuditSink()
    sink.append(_event(now))
    forged = _event(
        now + timedelta(seconds=1),
        id="audit-0002",
        subject_ref="case://AGE-0001",
        prev_event_digest=Digest(digest="f" * 64),  # does not match the real prior digest
    )
    with pytest.raises(AuditChainError):
        sink.append(forged)


def test_rejected_event_is_not_appended(now: datetime) -> None:
    sink = InMemoryAuditSink()
    sink.append(_event(now))
    forged = _event(now + timedelta(seconds=1), id="audit-0002")
    with pytest.raises(AuditChainError):
        sink.append(forged)
    assert len(sink.events_for_case("AGE-0001")) == 1


def test_events_are_isolated_per_case(now: datetime) -> None:
    sink = InMemoryAuditSink()
    sink.append(_event(now))
    other_case_event = _event(now, id="audit-9001", case_id="AGE-9999")
    sink.append(other_case_event)
    assert len(sink.events_for_case("AGE-0001")) == 1
    assert len(sink.events_for_case("AGE-9999")) == 1


def test_unknown_case_has_no_events() -> None:
    sink = InMemoryAuditSink()
    assert sink.events_for_case("AGE-0000") == ()
    assert sink.last_event("AGE-0000") is None


def test_audit_sink_exposes_no_delete_or_update_method() -> None:
    sink = InMemoryAuditSink()
    assert not hasattr(sink, "delete")
    assert not hasattr(sink, "update")
    assert not hasattr(sink, "remove")
