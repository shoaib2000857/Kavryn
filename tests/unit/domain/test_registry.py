from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from pydantic import ValidationError

from aegis.domain import Case, Digest
from aegis.domain.registry import SCHEMA_REGISTRY, UnknownSchemaVersionError, parse_record


def _case_data(now: datetime) -> dict[str, Any]:
    case = Case(
        id="AGE-0001",
        title="Path traversal in demo-api",
        created_at=now,
        created_by="operator:alice",
        scope_ref="scope://AGE-0001/1",
        scope_digest=Digest(digest="a" * 64),
    )
    return case.model_dump(mode="json")


def test_registry_covers_all_six_change_one_models() -> None:
    assert len(SCHEMA_REGISTRY) == 6
    assert {
        "aegis.case/v1",
        "aegis.scope_policy/v1",
        "aegis.evidence_envelope/v1",
        "aegis.action_request/v1",
        "aegis.policy_decision/v1",
        "aegis.audit_event/v1",
    } == set(SCHEMA_REGISTRY)


def test_parse_record_dispatches_by_schema_version(now: datetime) -> None:
    data = _case_data(now)
    record = parse_record(data)
    assert isinstance(record, Case)
    assert record.id == "AGE-0001"


def test_parse_record_fails_closed_on_unknown_version(now: datetime) -> None:
    data = _case_data(now)
    data["schema_version"] = "aegis.case/v99"
    with pytest.raises(UnknownSchemaVersionError):
        parse_record(data)


def test_parse_record_fails_closed_on_missing_version(now: datetime) -> None:
    data = _case_data(now)
    del data["schema_version"]
    with pytest.raises(UnknownSchemaVersionError):
        parse_record(data)


def test_parse_record_fails_closed_on_non_string_version(now: datetime) -> None:
    data = _case_data(now)
    data["schema_version"] = 1
    with pytest.raises(UnknownSchemaVersionError):
        parse_record(data)


def test_parse_record_does_not_silently_fall_back_to_any_model(now: datetime) -> None:
    """An attacker-controlled schema_version must never select an
    unintended model -- e.g. claiming to be a Case while shaped like an
    AuditEvent must fail validation against the Case schema, not quietly
    succeed as some other type."""
    data = _case_data(now)
    del data["title"]  # required by Case, not by AuditEvent
    with pytest.raises(ValidationError):
        parse_record(data)
