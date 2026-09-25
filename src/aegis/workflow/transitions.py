"""The explicit state transition table.

A direct transcription of every edge in docs/WORKFLOWS.md's closed-loop
incident-to-patch state diagram. ``apply_transition`` is pure and fails
closed: any (state, trigger) pair not in the table, or any trigger
attempted from a terminal state, raises ``InvalidTransitionError``
rather than silently no-op'ing or guessing a next state
(docs/AGENTS.md: "Keep orchestration deterministic and replayable.").
"""

from __future__ import annotations

from aegis.workflow.states import TERMINAL_STATES, CaseState, Trigger

__all__ = ["InvalidTransitionError", "allowed_triggers", "apply_transition"]

_S = CaseState
_T = Trigger

TRANSITIONS: dict[tuple[CaseState, Trigger], CaseState] = {
    (_S.INTAKE, _T.ADVANCE): _S.SCOPED,
    (_S.SCOPED, _T.ADVANCE): _S.OBSERVE,
    (_S.OBSERVE, _T.ADVANCE): _S.TRIAGE,
    (_S.TRIAGE, _T.ADVANCE): _S.INVESTIGATE,
    (_S.INVESTIGATE, _T.ADVANCE): _S.CONTAIN_PROPOSAL,
    (_S.CONTAIN_PROPOSAL, _T.RISK_REQUIRES_APPROVAL): _S.AWAIT_APPROVAL,
    (_S.CONTAIN_PROPOSAL, _T.POLICY_PERMITS): _S.CONTAIN,
    (_S.AWAIT_APPROVAL, _T.APPROVED): _S.CONTAIN,
    (_S.AWAIT_APPROVAL, _T.DENIED_OR_EXPIRED): _S.ESCALATED,
    (_S.CONTAIN, _T.ADVANCE): _S.CONTAINMENT_VERIFY,
    (_S.CONTAINMENT_VERIFY, _T.INEFFECTIVE_BUDGET_REMAINS): _S.INVESTIGATE,
    (_S.CONTAINMENT_VERIFY, _T.EFFECTIVE): _S.LOCALIZE,
    (_S.LOCALIZE, _T.ADVANCE): _S.REPAIR,
    (_S.REPAIR, _T.ADVANCE): _S.CANDIDATE_VERIFY,
    (_S.CANDIDATE_VERIFY, _T.REJECTED_BUDGET_REMAINS): _S.REPAIR,
    (_S.CANDIDATE_VERIFY, _T.VERIFIED): _S.AWAIT_DEPLOY_APPROVAL,
    (_S.CANDIDATE_VERIFY, _T.INSUFFICIENT_EVIDENCE): _S.ESCALATED,
    (_S.AWAIT_DEPLOY_APPROVAL, _T.APPROVED): _S.RECOVER,
    (_S.AWAIT_DEPLOY_APPROVAL, _T.DENIED_OR_EXPIRED): _S.ESCALATED,
    (_S.RECOVER, _T.ADVANCE): _S.RECOVERY_VERIFY,
    (_S.RECOVERY_VERIFY, _T.SUCCESSFUL): _S.MONITOR,
    (_S.RECOVERY_VERIFY, _T.FAILED): _S.ROLLBACK,
    (_S.ROLLBACK, _T.ADVANCE): _S.ESCALATED,
    (_S.MONITOR, _T.OBSERVATION_WINDOW_PASSES): _S.CLOSED,
    (_S.MONITOR, _T.RECURRENCE): _S.INVESTIGATE,
}


class InvalidTransitionError(ValueError):
    """Raised when a (state, trigger) pair has no defined transition."""


def allowed_triggers(state: CaseState) -> frozenset[Trigger]:
    """Return every trigger with a defined transition out of ``state``."""
    return frozenset(trigger for (from_state, trigger) in TRANSITIONS if from_state == state)


def apply_transition(state: CaseState, trigger: Trigger) -> CaseState:
    """Return the next state for ``(state, trigger)``, or fail closed.

    Raises ``InvalidTransitionError`` if ``state`` is terminal or the
    pair has no defined transition.
    """
    if state in TERMINAL_STATES:
        raise InvalidTransitionError(f"case state '{state.value}' is terminal; no transitions out")
    key = (state, trigger)
    if key not in TRANSITIONS:
        raise InvalidTransitionError(
            f"no transition for state '{state.value}' on trigger '{trigger.value}'"
        )
    return TRANSITIONS[key]
