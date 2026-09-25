from __future__ import annotations

import pytest

from aegis.workflow.states import TERMINAL_STATES, CaseState, Trigger
from aegis.workflow.transitions import (
    TRANSITIONS,
    InvalidTransitionError,
    allowed_triggers,
    apply_transition,
)


@pytest.mark.parametrize(
    ("state", "trigger", "expected"),
    [(state, trigger, expected) for (state, trigger), expected in TRANSITIONS.items()],
)
def test_every_documented_transition_applies(
    state: CaseState, trigger: Trigger, expected: CaseState
) -> None:
    assert apply_transition(state, trigger) is expected


def test_linear_happy_path_reaches_closed() -> None:
    state = CaseState.INTAKE
    path = [
        Trigger.ADVANCE,  # -> Scoped
        Trigger.ADVANCE,  # -> Observe
        Trigger.ADVANCE,  # -> Triage
        Trigger.ADVANCE,  # -> Investigate
        Trigger.ADVANCE,  # -> ContainProposal
        Trigger.POLICY_PERMITS,  # -> Contain
        Trigger.ADVANCE,  # -> ContainmentVerify
        Trigger.EFFECTIVE,  # -> Localize
        Trigger.ADVANCE,  # -> Repair
        Trigger.ADVANCE,  # -> CandidateVerify
        Trigger.VERIFIED,  # -> AwaitDeployApproval
        Trigger.APPROVED,  # -> Recover
        Trigger.ADVANCE,  # -> RecoveryVerify
        Trigger.SUCCESSFUL,  # -> Monitor
        Trigger.OBSERVATION_WINDOW_PASSES,  # -> Closed
    ]
    for trigger in path:
        state = apply_transition(state, trigger)
    assert state is CaseState.CLOSED


@pytest.mark.parametrize("state", sorted(TERMINAL_STATES, key=str))
def test_terminal_states_accept_no_further_transitions(state: CaseState) -> None:
    with pytest.raises(InvalidTransitionError):
        apply_transition(state, Trigger.ADVANCE)


def test_undefined_transition_raises() -> None:
    with pytest.raises(InvalidTransitionError):
        apply_transition(CaseState.INTAKE, Trigger.VERIFIED)


def test_allowed_triggers_matches_the_transition_table() -> None:
    assert allowed_triggers(CaseState.CONTAIN_PROPOSAL) == {
        Trigger.RISK_REQUIRES_APPROVAL,
        Trigger.POLICY_PERMITS,
    }


def test_allowed_triggers_is_empty_for_terminal_states() -> None:
    assert allowed_triggers(CaseState.CLOSED) == frozenset()
    assert allowed_triggers(CaseState.ESCALATED) == frozenset()


def test_containment_verify_can_loop_back_to_investigate_on_ineffective_result() -> None:
    next_state = apply_transition(CaseState.CONTAINMENT_VERIFY, Trigger.INEFFECTIVE_BUDGET_REMAINS)
    assert next_state is CaseState.INVESTIGATE


def test_recovery_failure_routes_through_rollback_to_escalated() -> None:
    rolled_back = apply_transition(CaseState.RECOVERY_VERIFY, Trigger.FAILED)
    assert rolled_back is CaseState.ROLLBACK
    escalated = apply_transition(rolled_back, Trigger.ADVANCE)
    assert escalated is CaseState.ESCALATED
