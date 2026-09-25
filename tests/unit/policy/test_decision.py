from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole
from aegis.domain.case import Case, CaseStatus
from aegis.domain.policy import PolicyDecision, PolicyOutcome, RiskTier
from aegis.domain.scope import ActionsPolicy, ScopePolicy
from aegis.policy.budget import BudgetUsage
from aegis.policy.decision import evaluate_action_request


def _request(now: datetime, **overrides: Any) -> ActionRequest:
    defaults: dict[str, Any] = {
        "id": "req-0001",
        "case_id": "AGE-0001",
        "actor_id": "reasoning_runtime:v1",
        "role": ActorRole.REASONING_RUNTIME,
        "action_type": "test.run",
        "target_ref": "workspace://AGE-0001/candidate/x",
        "adapter": "pytest.run",
        "parameters": {},
        "reason": "validate the fix",
        "requested_at": now,
    }
    defaults.update(overrides)
    return ActionRequest(**defaults)


def _evaluate(
    request: ActionRequest,
    case: Case,
    scope: ScopePolicy,
    now: datetime,
    *,
    usage: BudgetUsage | None = None,
    capability_ref: str | None = "capability://AGE-0001/cap-1",
) -> PolicyDecision:
    return evaluate_action_request(
        request,
        case=case,
        scope=scope,
        usage=usage or BudgetUsage(),
        now=now,
        decision_id="dec-0001",
        policy_version="scope-v1",
        capability_ref=capability_ref,
    )


def test_permitted_action_returns_capability_and_risk_tier(
    case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    decision = _evaluate(_request(now), case, scope_policy, now)
    assert decision.outcome is PolicyOutcome.PERMITTED
    assert decision.risk_tier is RiskTier.R2_VALIDATE
    assert decision.capability_ref == "capability://AGE-0001/cap-1"


def test_approval_required_action_never_carries_a_capability(
    case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    request = _request(now, action_type="deployment.rollout")
    decision = _evaluate(request, case, scope_policy, now)
    assert decision.outcome is PolicyOutcome.APPROVAL_REQUIRED
    assert decision.capability_ref is None


def test_denies_on_case_id_mismatch(case: Case, scope_policy: ScopePolicy, now: datetime) -> None:
    request = _request(now, case_id="AGE-9999")
    decision = _evaluate(request, case, scope_policy, now)
    assert decision.outcome is PolicyOutcome.DENIED
    assert decision.capability_ref is None


def test_denies_when_case_is_not_open(case: Case, scope_policy: ScopePolicy, now: datetime) -> None:
    stopped = case.model_copy(update={"status": CaseStatus.CONTROL_STOPPED})
    decision = _evaluate(_request(now), stopped, scope_policy, now)
    assert decision.outcome is PolicyOutcome.DENIED
    assert "not open" in decision.reasons[0]


def test_denies_when_scope_authorization_has_expired(
    case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    decision = _evaluate(_request(now), case, scope_policy, now + timedelta(days=30))
    assert decision.outcome is PolicyOutcome.DENIED
    assert "expired" in decision.reasons[0]


def test_denies_unlisted_action_type(case: Case, scope_policy: ScopePolicy, now: datetime) -> None:
    """FR-SCP-003 / Change 2: unsupported actions are denied."""
    request = _request(now, action_type="unlisted.thing")
    decision = _evaluate(request, case, scope_policy, now)
    assert decision.outcome is PolicyOutcome.DENIED
    assert "disposition" in decision.reasons[0]


def test_denies_explicitly_denied_action_type(
    case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    request = _request(now, action_type="host.shell", adapter="pytest.run")
    decision = _evaluate(request, case, scope_policy, now)
    assert decision.outcome is PolicyOutcome.DENIED
    assert "explicitly denied" in decision.reasons[0]


def test_denies_adapter_not_in_tool_allow_list(
    case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    request = _request(now, adapter="curl.raw")
    decision = _evaluate(request, case, scope_policy, now)
    assert decision.outcome is PolicyOutcome.DENIED
    assert "tool allow-list" in decision.reasons[0]


def test_denies_unresolved_target(case: Case, scope_policy: ScopePolicy, now: datetime) -> None:
    request = _request(now, target_ref="workspace://AGE-0001/somewhere-else/x")
    decision = _evaluate(request, case, scope_policy, now)
    assert decision.outcome is PolicyOutcome.DENIED
    assert "could not be resolved" in decision.reasons[0]


def test_r5_action_is_denied_even_if_scope_lists_it_as_auto(
    case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    """Defense in depth: a misconfigured or compromised scope policy that
    tries to auto-permit an R5 high-impact action must still be denied.
    Risk tiers are not scope-configurable (docs/CONTROL_PLANE.md)."""
    misconfigured = scope_policy.model_copy(
        update={
            "actions": ActionsPolicy(
                auto=("iam.admin",),
                approval=(),
                deny=(),
            )
        }
    )
    request = _request(now, action_type="iam.admin", adapter="pytest.run")
    decision = _evaluate(request, case, misconfigured, now)
    assert decision.outcome is PolicyOutcome.DENIED
    assert "R5" in decision.reasons[0]


def test_denies_action_type_with_no_known_risk_classification(
    case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    scope_with_unclassified_action = scope_policy.model_copy(
        update={
            "actions": ActionsPolicy(
                auto=(*scope_policy.actions.auto, "custom.unclassified"),
                approval=scope_policy.actions.approval,
                deny=scope_policy.actions.deny,
            )
        }
    )
    request = _request(now, action_type="custom.unclassified", adapter="pytest.run")
    decision = _evaluate(request, case, scope_with_unclassified_action, now)
    assert decision.outcome is PolicyOutcome.DENIED
    assert "risk classification" in decision.reasons[0]


def test_denies_when_budget_is_exhausted(
    case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    exhausted_usage = BudgetUsage(tool_calls=scope_policy.budgets.tool_calls)
    decision = _evaluate(_request(now), case, scope_policy, now, usage=exhausted_usage)
    assert decision.outcome is PolicyOutcome.DENIED
    assert "budget exhausted" in decision.reasons[0]


def test_denies_permitted_path_when_no_capability_was_issued(
    case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    decision = _evaluate(_request(now), case, scope_policy, now, capability_ref=None)
    assert decision.outcome is PolicyOutcome.DENIED
    assert "no capability" in decision.reasons[0]


def test_decision_reasons_are_never_empty(
    case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    decision = _evaluate(_request(now), case, scope_policy, now)
    assert len(decision.reasons) >= 1
