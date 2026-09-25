from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from aegis.domain import ActorRole, AuditEvent, AuditEventType, Digest


def _event_kwargs(now: datetime) -> dict[str, Any]:
    return {
        "id": "audit-0001",
        "case_id": "AGE-0001",
        "created_at": now,
        "event_type": AuditEventType.CASE_CREATED,
        "actor_id": "operator:alice",
        "role": ActorRole.OPERATOR,
        "subject_ref": "case://AGE-0001",
        "summary": "Case AGE-0001 created",
        "integrity": Digest(digest="a" * 64),
        "prev_event_digest": None,
    }


def test_first_event_has_no_predecessor(now: datetime) -> None:
    event = AuditEvent(**_event_kwargs(now))
    assert event.prev_event_digest is None


def test_event_round_trips_through_json(now: datetime) -> None:
    event = AuditEvent(**_event_kwargs(now))
    restored = AuditEvent.model_validate_json(event.model_dump_json())
    assert restored == event


def test_chained_event_references_previous_digest(now: datetime) -> None:
    first = AuditEvent(**_event_kwargs(now))
    second_kwargs = _event_kwargs(now + timedelta(seconds=1))
    second_kwargs["id"] = "audit-0002"
    second_kwargs["event_type"] = AuditEventType.ACTION_REQUESTED
    second_kwargs["subject_ref"] = "action-request://AGE-0001/req-0001"
    second_kwargs["prev_event_digest"] = first.integrity
    second = AuditEvent(**second_kwargs)
    assert second.prev_event_digest == first.integrity


def test_event_rejects_summary_over_length_limit(now: datetime) -> None:
    kwargs = _event_kwargs(now)
    kwargs["summary"] = "x" * 501
    with pytest.raises(ValidationError):
        AuditEvent(**kwargs)


def test_event_rejects_empty_summary(now: datetime) -> None:
    kwargs = _event_kwargs(now)
    kwargs["summary"] = ""
    with pytest.raises(ValidationError):
        AuditEvent(**kwargs)


def test_event_rejects_unknown_event_type(now: datetime) -> None:
    kwargs = _event_kwargs(now)
    kwargs["event_type"] = "case_deleted"
    with pytest.raises(ValidationError):
        AuditEvent(**kwargs)


def test_event_is_immutable(now: datetime) -> None:
    event = AuditEvent(**_event_kwargs(now))
    with pytest.raises(ValidationError):
        event.summary = "tampered"  # type: ignore[misc]
