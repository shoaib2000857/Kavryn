"""Human approval capture and resolution.

See docs/ARCHITECTURE.md's "Approval service" ("Captures human
identity, decision, expiry, and constraints") and
docs/CONTROL_PLANE.md's capability lifecycle
("AwaitingApproval --> Denied: rejected or expired",
"AwaitingApproval --> Issued: approved"). ``resolve_approval`` is pure
and maps an approval's current state to the two workflow triggers
docs/WORKFLOWS.md defines at every approval gate — or ``None`` while
still genuinely pending, so a caller knows not to transition yet
rather than guessing.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Final, Literal

from pydantic import model_validator

from aegis.domain.base import ActorId, AegisModel, AwareDatetime, CaseId, RecordId, Uri
from aegis.workflow.states import Trigger

__all__ = ["Approval", "ApprovalDecision", "resolve_approval"]

APPROVAL_SCHEMA_VERSION: Final[Literal["aegis.approval/v1"]] = "aegis.approval/v1"


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"


class Approval(AegisModel):
    schema_version: Literal["aegis.approval/v1"] = APPROVAL_SCHEMA_VERSION
    id: RecordId
    case_id: CaseId
    subject_ref: Uri
    requested_at: AwareDatetime
    expires_at: AwareDatetime
    decision: ApprovalDecision | None = None
    decided_by: ActorId | None = None
    decided_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _decision_fields_are_consistent(self) -> Approval:
        decided_fields = (self.decided_by, self.decided_at)
        if self.decision is None and any(f is not None for f in decided_fields):
            raise ValueError("decided_by/decided_at must be unset when there is no decision")
        if self.decision is not None and any(f is None for f in decided_fields):
            raise ValueError("decided_by and decided_at are required once a decision is recorded")
        return self


def resolve_approval(approval: Approval | None, *, now: datetime) -> Trigger | None:
    """Return the workflow trigger for this approval gate.

    ``None`` means genuinely still pending (no decision yet, not
    expired) — the caller must not transition. Every other case is
    unambiguous: no approval request at all, an explicit denial, or a
    timeout with no decision all fail closed to ``DENIED_OR_EXPIRED``;
    only an explicit ``APPROVED`` decision (regardless of how close to
    or past its own expiry the check happens) resolves to ``APPROVED``
    — expiry bounds how long a decision may be *awaited*, not how long
    an already-granted decision remains valid.
    """
    if approval is None:
        return None
    if approval.decision is ApprovalDecision.APPROVED:
        return Trigger.APPROVED
    if approval.decision is ApprovalDecision.DENIED:
        return Trigger.DENIED_OR_EXPIRED
    if now >= approval.expires_at:
        return Trigger.DENIED_OR_EXPIRED
    return None
