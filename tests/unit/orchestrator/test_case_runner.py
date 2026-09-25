from __future__ import annotations

import dataclasses
from collections.abc import Callable

from aegis.orchestrator.case_runner import CaseDependencies, run_case
from aegis.providers.base import ReasoningProvider
from aegis.providers.replay import ReplayProvider
from aegis.providers.schemas import (
    EvidenceContext,
    InferenceLimits,
    ReasoningTask,
    StructuredProposal,
    ToolDescriptor,
)
from aegis.providers.stub import StubProvider
from aegis.repair.candidate import PatchCandidate
from aegis.verifier.models import AssuranceOutcome
from aegis.workflow.states import CaseState
from tests.unit.conftest import CONTAINMENT_PROPOSAL, REFUSAL


class _RaisingProvider:
    """A provider stand-in whose ``propose`` always raises -- simulates a
    hosted provider that is unreachable, or (as found live against a real
    local model) one whose response never becomes schema-valid even after
    its own bounded-repair budget is exhausted."""

    async def propose(
        self,
        task: ReasoningTask,
        context: EvidenceContext,
        tools: tuple[ToolDescriptor, ...],
        limits: InferenceLimits,
    ) -> StructuredProposal:
        raise RuntimeError("provider unreachable")


def test_raising_provider_halts_gracefully_instead_of_crashing(
    happy_deps: CaseDependencies,
) -> None:
    provider: ReasoningProvider = _RaisingProvider()
    deps = dataclasses.replace(happy_deps, provider=provider)
    trace = run_case("AGE-0001", deps)
    assert trace.halted
    assert trace.final_state is CaseState.CONTAIN_PROPOSAL
    assert "provider error" in trace.halt_reason


def test_happy_path_reaches_closed(happy_deps: CaseDependencies) -> None:
    trace = run_case("AGE-0001", happy_deps)
    assert trace.final_state is CaseState.CLOSED
    assert not trace.halted


def _distinct_consecutive(states: list[CaseState]) -> list[CaseState]:
    """``trace.states`` has one entry per *note*, not per FSM transition
    (several notes can share a state); collapse consecutive repeats to
    get the actual sequence of distinct states visited."""
    result: list[CaseState] = []
    for state in states:
        if not result or result[-1] is not state:
            result.append(state)
    return result


def test_happy_path_visits_every_expected_state_in_order(happy_deps: CaseDependencies) -> None:
    trace = run_case("AGE-0001", happy_deps)
    assert len(trace.states) == len(trace.notes)
    assert _distinct_consecutive(trace.states) == [
        CaseState.INTAKE,
        CaseState.SCOPED,
        CaseState.OBSERVE,
        CaseState.TRIAGE,
        CaseState.INVESTIGATE,
        CaseState.CONTAIN_PROPOSAL,
        CaseState.AWAIT_APPROVAL,
        CaseState.CONTAIN,
        CaseState.CONTAINMENT_VERIFY,
        CaseState.LOCALIZE,
        CaseState.REPAIR,
        CaseState.CANDIDATE_VERIFY,
        CaseState.AWAIT_DEPLOY_APPROVAL,
        CaseState.RECOVER,
        CaseState.RECOVERY_VERIFY,
        CaseState.MONITOR,
        CaseState.CLOSED,
    ]


def test_provider_refusal_halts_at_contain_proposal_without_forcing_a_transition(
    happy_deps: CaseDependencies,
) -> None:
    deps = dataclasses.replace(happy_deps, provider=StubProvider(response=REFUSAL))
    trace = run_case("AGE-0001", deps)
    assert trace.halted
    assert trace.final_state is CaseState.CONTAIN_PROPOSAL


def test_containment_approval_denied_escalates(happy_deps: CaseDependencies) -> None:
    deps = dataclasses.replace(happy_deps, approve_containment=lambda: False)
    trace = run_case("AGE-0001", deps)
    assert trace.halted
    assert trace.final_state is CaseState.ESCALATED


def test_containment_ineffective_then_effective_on_retry_reaches_closed(
    happy_deps: CaseDependencies,
) -> None:
    attempts = iter([False, True])
    deps = dataclasses.replace(
        happy_deps,
        provider=ReplayProvider((CONTAINMENT_PROPOSAL, CONTAINMENT_PROPOSAL)),
        attack_blocked=lambda: next(attempts),
        max_containment_attempts=2,
    )
    trace = run_case("AGE-0001", deps)
    assert trace.final_state is CaseState.CLOSED
    assert not trace.halted


def test_containment_budget_exhausted_halts_at_containment_verify(
    happy_deps: CaseDependencies,
) -> None:
    deps = dataclasses.replace(happy_deps, attack_blocked=lambda: False, max_containment_attempts=1)
    trace = run_case("AGE-0001", deps)
    assert trace.halted
    assert trace.final_state is CaseState.CONTAINMENT_VERIFY
    assert "budget exhausted" in trace.halt_reason


def test_containment_effective_but_breaks_availability_triggers_rollback(
    happy_deps: CaseDependencies,
) -> None:
    rollback_calls: list[bool] = []
    deps = dataclasses.replace(
        happy_deps,
        benign_available=lambda: False,
        rollback_containment=lambda: rollback_calls.append(True),
        max_containment_attempts=1,
    )
    run_case("AGE-0001", deps)
    assert rollback_calls == [True]


def test_repair_rejected_then_verified_on_retry_reaches_closed(
    happy_deps: CaseDependencies, make_candidate: Callable[..., PatchCandidate]
) -> None:
    outcomes = iter([AssuranceOutcome.REJECTED, AssuranceOutcome.VERIFIED])
    deps = dataclasses.replace(
        happy_deps,
        verify_candidate=lambda _candidate: next(outcomes),
        max_repair_attempts=2,
    )
    trace = run_case("AGE-0001", deps)
    assert trace.final_state is CaseState.CLOSED
    assert not trace.halted


def test_repair_exhausted_escalates(happy_deps: CaseDependencies) -> None:
    deps = dataclasses.replace(
        happy_deps,
        verify_candidate=lambda _candidate: AssuranceOutcome.REJECTED,
        max_repair_attempts=1,
    )
    trace = run_case("AGE-0001", deps)
    assert trace.halted
    assert trace.final_state is CaseState.ESCALATED


def test_control_failure_escalates_immediately_without_retrying(
    happy_deps: CaseDependencies,
) -> None:
    calls: list[int] = []

    def verify(_candidate: PatchCandidate) -> AssuranceOutcome:
        calls.append(1)
        return AssuranceOutcome.CONTROL_FAILURE

    deps = dataclasses.replace(happy_deps, verify_candidate=verify, max_repair_attempts=3)
    trace = run_case("AGE-0001", deps)
    assert trace.halted
    assert trace.final_state is CaseState.ESCALATED
    assert len(calls) == 1  # never retried after a control failure


def test_deployment_approval_denied_escalates(happy_deps: CaseDependencies) -> None:
    deps = dataclasses.replace(happy_deps, approve_deployment=lambda: False)
    trace = run_case("AGE-0001", deps)
    assert trace.halted
    assert trace.final_state is CaseState.ESCALATED


def test_recovery_failure_rolls_back_and_escalates(happy_deps: CaseDependencies) -> None:
    deps = dataclasses.replace(happy_deps, recovery_attack_blocked=lambda: False)
    trace = run_case("AGE-0001", deps)
    assert trace.halted
    assert trace.final_state is CaseState.ESCALATED
    assert CaseState.ROLLBACK in trace.states


def test_recurrence_detected_halts_the_run_at_investigate(happy_deps: CaseDependencies) -> None:
    deps = dataclasses.replace(happy_deps, recurrence_detected=lambda: True)
    trace = run_case("AGE-0001", deps)
    assert trace.halted
    assert trace.final_state is CaseState.INVESTIGATE
