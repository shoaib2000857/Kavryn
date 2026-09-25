from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from pydantic import ValidationError

from aegis.domain import Classification, Digest, EvidenceEnvelope, Producer, ProducerType


def _envelope_kwargs(now: datetime) -> dict[str, Any]:
    return {
        "id": "ev-0001",
        "case_id": "AGE-0001",
        "created_at": now,
        "producer": Producer(type=ProducerType.ADAPTER, name="semgrep", version="1.90.0"),
        "subject_refs": ("asset://demo-api",),
        "integrity": Digest(digest="a" * 64),
        "classification": Classification.INTERNAL,
        "payload": {"finding": "CWE-22", "line": 42},
    }


def test_valid_evidence_envelope_round_trips(now: datetime) -> None:
    envelope = EvidenceEnvelope(**_envelope_kwargs(now))
    restored = EvidenceEnvelope.model_validate_json(envelope.model_dump_json())
    assert restored == envelope


def test_evidence_envelope_requires_explicit_classification(now: datetime) -> None:
    kwargs = _envelope_kwargs(now)
    del kwargs["classification"]
    with pytest.raises(ValidationError):
        EvidenceEnvelope(**kwargs)


def test_evidence_envelope_requires_at_least_one_subject(now: datetime) -> None:
    kwargs = _envelope_kwargs(now)
    kwargs["subject_refs"] = ()
    with pytest.raises(ValidationError):
        EvidenceEnvelope(**kwargs)


def test_evidence_envelope_rejects_non_uri_subject_ref(now: datetime) -> None:
    kwargs = _envelope_kwargs(now)
    kwargs["subject_refs"] = ("demo-api",)  # missing scheme
    with pytest.raises(ValidationError):
        EvidenceEnvelope(**kwargs)


def test_evidence_envelope_defaults_source_refs_to_empty(now: datetime) -> None:
    envelope = EvidenceEnvelope(**_envelope_kwargs(now))
    assert envelope.source_refs == ()


def test_evidence_envelope_payload_defaults_to_empty_dict(now: datetime) -> None:
    kwargs = _envelope_kwargs(now)
    del kwargs["payload"]
    envelope = EvidenceEnvelope(**kwargs)
    assert envelope.payload == {}
