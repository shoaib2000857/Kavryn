"""The pure policy decision function.

See docs/IMPLEMENTATION_HANDOFF.md Change 2 and docs/CONTROL_PLANE.md
"Authorization tuple": every field the tuple names (case, actor, role,
action_type, target, parameters, state, capability, risk_tier, budget,
approval, time, policy_version) is either an input to
``evaluate_action_request`` or an output field on the ``PolicyDecision``
it returns. "An omitted or ambiguous field causes denial" is the
guiding rule throughout: every branch below either resolves a field
unambiguously or returns ``DENIED``/``APPROVAL_REQUIRED``.

This function is deterministic and pure: no I/O, no clock access beyond
the ``now`` parameter, no hidden state. It requires no LLM and is fully
unit-testable (docs/PRODUCT_REQUIREMENTS.md QR-TST-001).
"""

from __future__ import annotations

from datetime import datetime

from aegis.domain.action import ActionRequest
from aegis.domain.case import Case, CaseStatus
from aegis.domain.policy import PolicyDecision, PolicyOutcome, RiskTier
from aegis.domain.scope import ScopePolicy
from aegis.policy.approval import Approval, ApprovalDecision
from aegis.policy.budget import BudgetUsage, exhausted_dimensions
from aegis.policy.risk import classify_risk
from aegis.policy.targets import resolve_target

__all__ = ["evaluate_action_request"]


def _denied(
    *,
    decision_id: str,
    case_id: str,
    request_id: str,
    decided_at: datetime,
    policy_version: str,
    risk_tier: RiskTier,
    reason: str,
) -> PolicyDecision:
    return PolicyDecision(
        id=decision_id,
        case_id=case_id,
        request_id=request_id,
        decided_at=decided_at,
        policy_version=policy_version,
        risk_tier=risk_tier,
        outcome=PolicyOutcome.DENIED,
        reasons=(reason,),
        capability_ref=None,
    )


def evaluate_action_request(
    request: ActionRequest,
    *,
    case: Case,
    scope: ScopePolicy,
    usage: BudgetUsage,
    now: datetime,
    decision_id: str,
    policy_version: str,
    capability_ref: str | None = None,
    approval: Approval | None = None,
) -> PolicyDecision:
    """Evaluate one ``ActionRequest`` against case, scope, and budget state.

    ``capability_ref`` must be supplied by the caller (the action broker
    owns capability issuance in a later change) and is only ever
    attached to the returned decision when the outcome is ``PERMITTED``;
    it is ignored otherwise. Every unresolved or ambiguous condition
    below denies rather than guesses, per FR-SCP-003.
    """
    # An unrecognized action type has no risk classification and is
    # denied before any other check runs, so every denial reason below
    # can cite a concrete, known risk tier.
    unclassified_risk = classify_risk(request.action_type)
    fallback_risk = unclassified_risk or RiskTier.R5_HIGH_IMPACT

    def deny(reason: str) -> PolicyDecision:
        return _denied(
            decision_id=decision_id,
            case_id=case.id,
            request_id=request.id,
            decided_at=now,
            policy_version=policy_version,
            risk_tier=fallback_risk,
            reason=reason,
        )

    if scope.case_id != case.id or request.case_id != case.id:
        return deny("case, scope, and request case_id must all match")

    if case.status is not CaseStatus.OPEN:
        return deny(f"case status is '{case.status.value}', not open")

    if now >= scope.authorization.expires_at:
        return deny("scope authorization has expired")

    disposition = _disposition(request.action_type, scope)
    if disposition is None:
        return deny("action_type has no explicit disposition (auto/approval/deny) in scope")
    if disposition == "deny":
        return deny("action_type is explicitly denied by scope policy")

    if request.adapter not in scope.tools.allow:
        return deny("adapter is not in the scope tool allow-list")

    resolution = resolve_target(request.target_ref, scope)
    if not resolution.resolved:
        return deny(
            f"target could not be resolved to an explicit scope object: {resolution.reason}"
        )

    if unclassified_risk is None:
        return deny("action_type has no known risk classification")
    risk_tier = unclassified_risk

    if risk_tier is RiskTier.R5_HIGH_IMPACT:
        return deny("R5 high-impact actions are denied unconditionally in this system")

    exceeded = exhausted_dimensions(scope.budgets, usage)
    if exceeded:
        return deny(f"budget exhausted: {', '.join(exceeded)}")

    if disposition == "approval":
        if approval is None:
            return PolicyDecision(
                id=decision_id,
                case_id=case.id,
                request_id=request.id,
                decided_at=now,
                policy_version=policy_version,
                risk_tier=risk_tier,
                outcome=PolicyOutcome.APPROVAL_REQUIRED,
                reasons=("action_type requires human approval per scope policy",),
                capability_ref=None,
            )
        expected_subject = f"action-request://{case.id}/{request.id}"
        if approval.case_id != case.id or approval.subject_ref != expected_subject:
            return deny("approval does not bind to this case and exact action request")
        if approval.decision is not ApprovalDecision.APPROVED:
            return deny("approval is absent, pending, or denied")
        if approval.decided_at is None or approval.decided_by is None:
            return deny("approval decision is missing attribution")
        if approval.decided_by == request.actor_id:
            return deny("the requesting actor cannot approve its own action")
        if approval.requested_at > now or approval.decided_at > now:
            return deny("approval timestamps are in the future")
        if approval.decided_at >= approval.expires_at or now >= approval.expires_at:
            return deny("approval is expired")
        if capability_ref is None:
            return deny("no capability was issued for this approved decision")

    if capability_ref is None:
        return deny("no capability was issued for this permitted decision")

    return PolicyDecision(
        id=decision_id,
        case_id=case.id,
        request_id=request.id,
        decided_at=now,
        policy_version=policy_version,
        risk_tier=risk_tier,
        outcome=PolicyOutcome.PERMITTED,
        reasons=(
            "required approval was verified; action_type, adapter, target, and budget resolved"
            if disposition == "approval"
            else "action_type, adapter, target, and budget all resolved within scope",
        ),
        capability_ref=capability_ref,
    )


def _disposition(action_type: str, scope: ScopePolicy) -> str | None:
    if action_type in scope.actions.deny:
        return "deny"
    if action_type in scope.actions.approval:
        return "approval"
    if action_type in scope.actions.auto:
        return "auto"
    return None
