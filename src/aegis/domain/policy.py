"""The PolicyDecision record: the deterministic policy engine's verdict.

See docs/CONTROL_PLANE.md "Risk tiers" and "Capability lifecycle". This
change models the decision record only; the pure decision function that
produces one is docs/IMPLEMENTATION_HANDOFF.md Change 2.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Final, Literal

from pydantic import StringConstraints, model_validator

from aegis.domain.base import AegisModel, AwareDatetime, CaseId, Reason, RecordId, Uri

__all__ = ["PolicyDecision", "PolicyOutcome", "RiskTier"]

POLICY_DECISION_SCHEMA_VERSION: Final[Literal["aegis.policy_decision/v1"]] = (
    "aegis.policy_decision/v1"
)


class RiskTier(StrEnum):
    """Risk tiers from docs/CONTROL_PLANE.md, assigned by policy, not the model."""

    R0_OBSERVE = "r0_observe"
    R1_ANALYZE = "r1_analyze"
    R2_VALIDATE = "r2_validate"
    R3_REVERSIBLE_RESPONSE = "r3_reversible_response"
    R4_CHANGE = "r4_change"
    R5_HIGH_IMPACT = "r5_high_impact"


class PolicyOutcome(StrEnum):
    """The three terminal-or-pending dispositions of a policy evaluation."""

    PERMITTED = "permitted"
    DENIED = "denied"
    APPROVAL_REQUIRED = "approval_required"


class PolicyDecision(AegisModel):
    """The outcome of evaluating one ``ActionRequest`` against scope and policy.

    A capability reference may only be present when the outcome is
    ``PERMITTED`` (docs/CONTROL_PLANE.md capability lifecycle: a
    capability is only ``Issued`` when a request is "permitted"). A
    denied or approval-pending decision that carried a capability would
    be a control-plane integrity failure, so it is rejected here.
    """

    schema_version: Literal["aegis.policy_decision/v1"] = POLICY_DECISION_SCHEMA_VERSION
    id: RecordId
    case_id: CaseId
    request_id: RecordId
    decided_at: AwareDatetime
    policy_version: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    risk_tier: RiskTier
    outcome: PolicyOutcome
    reasons: tuple[Reason, ...]
    capability_ref: Uri | None = None

    @model_validator(mode="after")
    def _reasons_required(self) -> PolicyDecision:
        if not self.reasons:
            raise ValueError("a policy decision must state at least one reason")
        return self

    @model_validator(mode="after")
    def _capability_only_when_permitted(self) -> PolicyDecision:
        if self.outcome is PolicyOutcome.PERMITTED and self.capability_ref is None:
            raise ValueError("a permitted decision must reference an issued capability")
        if self.outcome is not PolicyOutcome.PERMITTED and self.capability_ref is not None:
            raise ValueError(f"a '{self.outcome.value}' decision must not reference a capability")
        return self
