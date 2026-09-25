from __future__ import annotations

from aegis.domain.policy import PolicyOutcome, RiskTier
from aegis.monitoring.behavioral import (
    AdvisoryDisposition,
    BehavioralMonitor,
    BehavioralObservation,
)


def observation(
    request_id: str,
    *,
    action_type: str = "evidence.read",
    outcome: PolicyOutcome = PolicyOutcome.PERMITTED,
    risk_tier: RiskTier = RiskTier.R0_OBSERVE,
) -> BehavioralObservation:
    return BehavioralObservation(
        request_id=request_id,
        case_id="AGE-0001",
        actor_id="reasoning_runtime:v1",
        action_type=action_type,
        outcome=outcome,
        risk_tier=risk_tier,
    )


def test_safe_low_risk_requests_remain_at_continue_advisory() -> None:
    result = BehavioralMonitor().observe(observation("req-1"))
    assert result.disposition is AdvisoryDisposition.CONTINUE
    assert result.score == 0.0
    assert "policy_denial_observed" not in result.signals


def test_repeated_denials_raise_an_advisory_without_changing_policy() -> None:
    monitor = BehavioralMonitor()
    monitor.observe(observation("req-1", outcome=PolicyOutcome.DENIED))
    result = monitor.observe(observation("req-2", outcome=PolicyOutcome.DENIED))
    assert result.disposition is AdvisoryDisposition.REDUCE_AUTONOMY
    assert result.features["policy_denials"] == 2
    assert result.features["repeated_denials_same_action"] == 1
    assert "repeated_denial_same_action" in result.signals


def test_high_impact_and_repeated_denials_raise_human_review_signal() -> None:
    monitor = BehavioralMonitor()
    for index in range(2):
        monitor.observe(
            observation(
                f"req-{index}",
                action_type="deployment.rollout",
                outcome=PolicyOutcome.DENIED,
                risk_tier=RiskTier.R4_CHANGE,
            )
        )
    result = monitor.observe(
        observation(
            "req-3",
            action_type="deployment.rollback",
            outcome=PolicyOutcome.APPROVAL_REQUIRED,
            risk_tier=RiskTier.R4_CHANGE,
        )
    )
    assert result.disposition is AdvisoryDisposition.HUMAN_REVIEW
    assert result.features["high_impact_requests"] == 3
    assert result.features["approval_pending"] == 1


def test_reobservation_of_same_request_is_idempotent() -> None:
    monitor = BehavioralMonitor()
    event = observation("req-1", outcome=PolicyOutcome.DENIED)
    first = monitor.observe(event)
    second = monitor.observe(event)
    assert second == first
    assert second.observation_count == 1


def test_history_window_is_bounded() -> None:
    monitor = BehavioralMonitor(window_size=2)
    monitor.observe(observation("req-1", outcome=PolicyOutcome.DENIED))
    monitor.observe(observation("req-2", outcome=PolicyOutcome.DENIED))
    result = monitor.observe(observation("req-3"))
    assert result.observation_count == 2
    assert result.features["policy_denials"] == 1
