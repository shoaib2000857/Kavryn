"""The Case record: a case-specific authorization boundary.

See docs/PRODUCT_REQUIREMENTS.md FR-SCP-001 and docs/ARCHITECTURE.md
("Case service | Case lifecycle and immutable scope reference").
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Final, Literal

from pydantic import StringConstraints

from aegis.domain.base import ActorId, AegisModel, AwareDatetime, CaseId, Digest, Uri

__all__ = ["Case", "CaseStatus"]

CASE_SCHEMA_VERSION: Final[Literal["aegis.case/v1"]] = "aegis.case/v1"


class CaseStatus(StrEnum):
    """Case lifecycle status.

    Only the statuses needed to model the emergency-stop invariant in
    docs/CONTROL_PLANE.md are included here. The full workflow state
    machine (docs/IMPLEMENTATION_HANDOFF.md, Change 2) is out of scope
    for this change.
    """

    OPEN = "open"
    CONTROL_STOPPED = "control_stopped"
    CLOSED = "closed"


class Case(AegisModel):
    """A case: the unit of authorization, evidence, and audit scoping.

    A case never embeds its scope policy inline; it carries a reference
    and a content digest so the policy can be stored, hashed, and
    audited independently (docs/ARCHITECTURE.md, data-flow step 2:
    "Case service creates a case and hashes the scope policy.").
    """

    schema_version: Literal["aegis.case/v1"] = CASE_SCHEMA_VERSION
    id: CaseId
    title: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    status: CaseStatus = CaseStatus.OPEN
    created_at: AwareDatetime
    created_by: ActorId
    scope_ref: Uri
    scope_digest: Digest
