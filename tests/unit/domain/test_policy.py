from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from pydantic import ValidationError

from aegis.domain import PolicyDecision, PolicyOutcome, RiskTier


def _decision_kwargs(now: datetime) -> dict[str, Any]:
    return {
        "id": "dec-0001",
        "case_id": "AGE-0001",
        "request_id": "req-0001",
        "decided_at": now,
        "policy_version": "scope-v1+engine-v1",
        "risk_tier": RiskTier.R2_VALIDATE,
        "outcome": PolicyOutcome.PERMITTED,
        "reasons": ("within tools.allow and R2 auto-tier",),
        "capability_ref": "capability://AGE-0001/cap-1",
    }


def test_valid_permitted_decision_round_trips(now: datetime) -> None:
    decision = PolicyDecision(**_decision_kwargs(now))
    restored = PolicyDecision.model_validate_json(decision.model_dump_json())
    assert restored == decision


def test_permitted_decision_requires_capability(now: datetime) -> None:
    kwargs = _decision_kwargs(now)
    kwargs["capability_ref"] = None
    with pytest.raises(ValidationError, match="must reference an issued capability"):
        PolicyDecision(**kwargs)


@pytest.mark.parametrize("outcome", [PolicyOutcome.DENIED, PolicyOutcome.APPROVAL_REQUIRED])
def test_non_permitted_decision_forbids_capability(now: datetime, outcome: PolicyOutcome) -> None:
    """A denied or pending decision must never carry an issued capability.

    This is the schema-level guard against a forged or tampered decision
    record smuggling authority it was never granted (SR-AUT-001).
    """
    kwargs = _decision_kwargs(now)
    kwargs["outcome"] = outcome
    kwargs["reasons"] = ("out of scope",)
    with pytest.raises(ValidationError, match="must not reference a capability"):
        PolicyDecision(**kwargs)


def test_denied_decision_without_capability_is_valid(now: datetime) -> None:
    kwargs = _decision_kwargs(now)
    kwargs["outcome"] = PolicyOutcome.DENIED
    kwargs["capability_ref"] = None
    kwargs["reasons"] = ("target not resolvable to an explicit scope object",)
    decision = PolicyDecision(**kwargs)
    assert decision.outcome is PolicyOutcome.DENIED


def test_decision_requires_at_least_one_reason(now: datetime) -> None:
    kwargs = _decision_kwargs(now)
    kwargs["reasons"] = ()
    with pytest.raises(ValidationError, match="at least one reason"):
        PolicyDecision(**kwargs)


def test_decision_rejects_unknown_risk_tier(now: datetime) -> None:
    kwargs = _decision_kwargs(now)
    kwargs["risk_tier"] = "r6_omnipotent"
    with pytest.raises(ValidationError):
        PolicyDecision(**kwargs)
