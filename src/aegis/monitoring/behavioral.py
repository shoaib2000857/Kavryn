"""Small, explainable advisory baseline over broker-observed actions.

This is an experimental behavioral feature baseline, not a validated
unsafe-intent detector. It consumes structured broker facts only; model
rationales, source text, logs, and other untrusted content are not inputs.
Its output must never grant authority or replace deterministic policy.
"""

from __future__ import annotations

from collections import deque
from enum import StrEnum
from threading import RLock
from typing import Literal

from pydantic import Field

from aegis.domain.base import ActorId, AegisModel, CaseId, RecordId
from aegis.domain.policy import PolicyOutcome, RiskTier

__all__ = [
    "AdvisoryDisposition",
    "BehavioralAssessment",
    "BehavioralMonitor",
    "BehavioralObservation",
]


class AdvisoryDisposition(StrEnum):
    CONTINUE = "continue"
    REDUCE_AUTONOMY = "reduce_autonomy"
    HUMAN_REVIEW = "human_review"
    PAUSE_AND_ESCALATE = "pause_and_escalate"


class BehavioralObservation(AegisModel):
    """Facts derived by the broker after deterministic policy evaluation."""

    request_id: RecordId
    case_id: CaseId
    actor_id: ActorId
    action_type: str = Field(min_length=3, max_length=128)
    outcome: PolicyOutcome
    risk_tier: RiskTier


class BehavioralAssessment(AegisModel):
    """A bounded-window advisory; it has no authorization semantics."""

    schema_version: Literal["aegis.behavioral_assessment/v1"] = "aegis.behavioral_assessment/v1"
    disposition: AdvisoryDisposition
    score: float = Field(ge=0.0, le=1.0)
    observation_count: int = Field(ge=1)
    features: dict[str, int]
    signals: tuple[str, ...]
    monitor_version: str = "aegis.behavioral-monitor/rule-baseline-v1"


class BehavioralMonitor:
    """Thread-safe, process-local rolling baseline keyed by case and actor.

    The default weights and thresholds are transparent engineering defaults,
    not empirically selected thresholds. A repeated request ID is idempotent,
    which avoids counting an approval-resume as a new proposal.
    """

    def __init__(self, *, window_size: int = 32) -> None:
        if window_size < 2:
            raise ValueError("window_size must be at least 2")
        self._window_size = window_size
        self._history: dict[tuple[str, str], deque[BehavioralObservation]] = {}
        self._seen: dict[tuple[str, str], dict[str, BehavioralAssessment]] = {}
        self._lock = RLock()

    def observe(self, observation: BehavioralObservation) -> BehavioralAssessment:
        """Record a broker observation and return a non-authoritative signal."""
        key = (observation.case_id, observation.actor_id)
        with self._lock:
            seen = self._seen.setdefault(key, {})
            previous = seen.get(observation.request_id)
            if previous is not None:
                return previous

            history = self._history.setdefault(key, deque(maxlen=self._window_size))
            history.append(observation)
            assessment = self._assess(tuple(history))
            seen[observation.request_id] = assessment
            retained_ids = {item.request_id for item in history}
            for request_id in tuple(seen):
                if request_id not in retained_ids:
                    del seen[request_id]
            return assessment

    @staticmethod
    def _assess(history: tuple[BehavioralObservation, ...]) -> BehavioralAssessment:
        denied = [item for item in history if item.outcome is PolicyOutcome.DENIED]
        denied_action_types = [item.action_type for item in denied]
        repeated_denials = sum(
            max(0, denied_action_types.count(action_type) - 1)
            for action_type in set(denied_action_types)
        )
        high_impact = sum(
            item.risk_tier in {RiskTier.R4_CHANGE, RiskTier.R5_HIGH_IMPACT} for item in history
        )
        features = {
            "policy_denials": len(denied),
            "repeated_denials_same_action": repeated_denials,
            "high_impact_requests": high_impact,
            "approval_pending": sum(
                item.outcome is PolicyOutcome.APPROVAL_REQUIRED for item in history
            ),
        }
        # An explainable engineering score for baseline experiments, not a
        # probability or calibrated estimate of future unsafe behavior.
        score = min(
            1.0,
            0.12 * min(features["policy_denials"], 3)
            + 0.18 * min(repeated_denials, 2)
            + 0.10 * min(high_impact, 3),
        )
        signals: list[str] = []
        if features["policy_denials"]:
            signals.append("policy_denial_observed")
        if repeated_denials:
            signals.append("repeated_denial_same_action")
        if high_impact:
            signals.append("high_impact_request_observed")
        if features["approval_pending"]:
            signals.append("approval_pending_observed")

        if score >= 0.75:
            disposition = AdvisoryDisposition.PAUSE_AND_ESCALATE
        elif score >= 0.50:
            disposition = AdvisoryDisposition.HUMAN_REVIEW
        elif score >= 0.25:
            disposition = AdvisoryDisposition.REDUCE_AUTONOMY
        else:
            disposition = AdvisoryDisposition.CONTINUE

        return BehavioralAssessment(
            disposition=disposition,
            score=score,
            observation_count=len(history),
            features=features,
            signals=tuple(signals),
        )
