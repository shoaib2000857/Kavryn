"""Case workflow states and triggers.

Enumerates exactly the states and edges of the closed-loop
incident-to-patch state machine in docs/WORKFLOWS.md ("Closed-loop
incident-to-patch workflow"). This is deliberately a direct transcription
of that diagram, not a reinterpretation.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["TERMINAL_STATES", "CaseState", "Trigger"]


class CaseState(StrEnum):
    INTAKE = "intake"
    SCOPED = "scoped"
    OBSERVE = "observe"
    TRIAGE = "triage"
    INVESTIGATE = "investigate"
    CONTAIN_PROPOSAL = "contain_proposal"
    AWAIT_APPROVAL = "await_approval"
    CONTAIN = "contain"
    CONTAINMENT_VERIFY = "containment_verify"
    LOCALIZE = "localize"
    REPAIR = "repair"
    CANDIDATE_VERIFY = "candidate_verify"
    AWAIT_DEPLOY_APPROVAL = "await_deploy_approval"
    RECOVER = "recover"
    RECOVERY_VERIFY = "recovery_verify"
    MONITOR = "monitor"
    ROLLBACK = "rollback"
    CLOSED = "closed"
    ESCALATED = "escalated"


TERMINAL_STATES = frozenset({CaseState.CLOSED, CaseState.ESCALATED})


class Trigger(StrEnum):
    """Named edges from docs/WORKFLOWS.md's state diagram.

    ``ADVANCE`` covers every unlabeled edge in the diagram (a plain
    stage completion with no branch); every other member corresponds to
    exactly one labeled edge.
    """

    ADVANCE = "advance"
    RISK_REQUIRES_APPROVAL = "risk_requires_approval"
    POLICY_PERMITS = "policy_permits"
    APPROVED = "approved"
    DENIED_OR_EXPIRED = "denied_or_expired"
    INEFFECTIVE_BUDGET_REMAINS = "ineffective_budget_remains"
    EFFECTIVE = "effective"
    REJECTED_BUDGET_REMAINS = "rejected_budget_remains"
    VERIFIED = "verified"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    SUCCESSFUL = "successful"
    FAILED = "failed"
    OBSERVATION_WINDOW_PASSES = "observation_window_passes"
    RECURRENCE = "recurrence"
