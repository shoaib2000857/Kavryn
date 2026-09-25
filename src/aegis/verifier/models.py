"""Assurance decision types.

See docs/PRODUCT_REQUIREMENTS.md FR-ASR-003 (the four terminal
decisions) and docs/EVIDENCE_AND_ASSURANCE.md "Assurance decisions".
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

from pydantic import Field

from aegis.domain.base import AegisModel, AwareDatetime, CaseId, Digest, RecordId

__all__ = ["AssuranceBundle", "AssuranceOutcome", "CheckResult", "CheckStatus"]

ASSURANCE_BUNDLE_SCHEMA_VERSION: Final[Literal["aegis.assurance_bundle/v1"]] = (
    "aegis.assurance_bundle/v1"
)


class AssuranceOutcome(StrEnum):
    VERIFIED = "verified"
    REVIEW_REQUIRED = "review_required"
    REJECTED = "rejected"
    CONTROL_FAILURE = "control_failure"


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


class CheckResult(AegisModel):
    """One check's outcome from the assurance profile.

    ``hard_failure`` marks a check whose ``FAIL`` is non-compensating
    (docs/EVIDENCE_AND_ASSURANCE.md "Hard failures") — it can never be
    outweighed by other passing checks or by model confidence.
    """

    check_id: str = Field(min_length=1, max_length=100)
    status: CheckStatus
    hard_failure: bool
    detail: str = Field(max_length=4000)


class AssuranceBundle(AegisModel):
    """The evidence-carrying patch bundle (FR-ASR-004)."""

    schema_version: Literal["aegis.assurance_bundle/v1"] = ASSURANCE_BUNDLE_SCHEMA_VERSION
    case_id: CaseId
    candidate_id: RecordId
    candidate_digest: Digest
    decided_at: AwareDatetime
    outcome: AssuranceOutcome
    checks: tuple[CheckResult, ...] = Field(min_length=1)
