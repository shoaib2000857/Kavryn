"""The AuditEvent record: an append-only, hash-chained audit entry.

See docs/PRODUCT_REQUIREMENTS.md SR-AUD-001/SR-AUD-002 and
docs/THREAT_MODEL.md T07 (audit tampering). This change models the
record shape only; the append-only storage guarantee (an external sink
the reasoning runtime cannot delete or rewrite) is an infrastructure
property to be built in a later change, not something a Pydantic model
can enforce by itself. The hash chain gives that later store a concrete,
verifiable tamper-evidence mechanism: each event digests the previous
event, so any deletion or rewrite breaks the chain.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Final, Literal

from pydantic import StringConstraints

from aegis.domain.base import (
    ActorId,
    ActorRole,
    AegisModel,
    AwareDatetime,
    CaseId,
    Digest,
    RecordId,
    Uri,
)

__all__ = ["AuditEvent", "AuditEventType"]

AUDIT_EVENT_SCHEMA_VERSION: Final[Literal["aegis.audit_event/v1"]] = "aegis.audit_event/v1"


class AuditEventType(StrEnum):
    """A controlled vocabulary of auditable lifecycle events.

    Limited, for this change, to events over the records introduced
    here (case, action request, policy decision, evidence). New event
    types are additive and do not require a schema version bump.
    """

    CASE_CREATED = "case_created"
    CASE_CONTROL_STOPPED = "case_control_stopped"
    CASE_CLOSED = "case_closed"
    ACTION_REQUESTED = "action_requested"
    POLICY_DECISION_RECORDED = "policy_decision_recorded"
    EVIDENCE_RECORDED = "evidence_recorded"
    TOOL_RUN_RECORDED = "tool_run_recorded"


class AuditEvent(AegisModel):
    """One append-only, hash-chained audit record.

    ``prev_event_digest`` is ``None`` only for the first event recorded
    for a case; every subsequent event must reference the digest of the
    event immediately before it.
    """

    schema_version: Literal["aegis.audit_event/v1"] = AUDIT_EVENT_SCHEMA_VERSION
    id: RecordId
    case_id: CaseId
    created_at: AwareDatetime
    event_type: AuditEventType
    actor_id: ActorId
    role: ActorRole
    subject_ref: Uri
    summary: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    integrity: Digest
    prev_event_digest: Digest | None = None
