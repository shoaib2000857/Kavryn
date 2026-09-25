"""The EvidenceEnvelope record: the minimal common envelope for evidence.

See docs/EVIDENCE_AND_ASSURANCE.md "Minimal common envelope". This
change models the envelope only; typed payload schemas for specific
evidence kinds (findings, tool runs, hypotheses, ...) are deferred to
later changes rather than invented here.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Final, Literal

from pydantic import Field

from aegis.domain.base import AegisModel, AwareDatetime, CaseId, Digest, Producer, RecordId, Uri

__all__ = ["Classification", "EvidenceEnvelope"]

EVIDENCE_ENVELOPE_SCHEMA_VERSION: Final[Literal["aegis.evidence_envelope/v1"]] = (
    "aegis.evidence_envelope/v1"
)


class Classification(StrEnum):
    """Data-sensitivity label carried on every evidence record.

    docs/OPEN_QUESTIONS.md OQ-005 leaves open which classifications may
    leave the local environment; this enum only names the labels used to
    tag evidence, it does not decide any egress policy for them.
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"


class EvidenceEnvelope(AegisModel):
    """A single content-addressed, provenance-carrying evidence record.

    ``classification`` has no default: FR-ING-002 and SR-SEC-001 require
    every producer to make an explicit sensitivity decision rather than
    inheriting a silent default.
    """

    schema_version: Literal["aegis.evidence_envelope/v1"] = EVIDENCE_ENVELOPE_SCHEMA_VERSION
    id: RecordId
    case_id: CaseId
    created_at: AwareDatetime
    producer: Producer
    subject_refs: tuple[Uri, ...] = Field(min_length=1)
    source_refs: tuple[Uri, ...] = ()
    integrity: Digest
    classification: Classification
    payload: dict[str, Any] = Field(default_factory=dict)
