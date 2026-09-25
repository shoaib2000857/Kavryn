from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable

from aegis.orchestrator.actions import BrokeredDefenderActions
from aegis.orchestrator.case_runner import CaseDependencies, run_case
from aegis.policy.approval import ApprovalDecision
from aegis.reporting.case_report import render_human_report, render_json_report
from aegis.workflow.states import CaseState


def test_json_report_round_trips_and_matches_the_trace(happy_deps: CaseDependencies) -> None:
    trace = run_case("AGE-0001", happy_deps)
    payload = json.loads(render_json_report(trace))
    assert payload["case_id"] == "AGE-0001"
    assert payload["final_state"] == CaseState.CLOSED.value
    assert payload["halted"] is False
    assert payload["states"][0] == CaseState.INTAKE.value
    assert payload["states"][-1] == CaseState.CLOSED.value
    assert len(payload["states"]) == len(payload["notes"])
    assert payload["investigation"]["case_id"] == "AGE-0001"
    assert payload["investigation"]["hypotheses"][0]["status"] == "hypothesis"


def test_human_report_names_the_outcome_and_lists_every_state(
    happy_deps: CaseDependencies,
) -> None:
    trace = run_case("AGE-0001", happy_deps)
    report = render_human_report(trace)
    assert "AGE-0001" in report
    assert "completed at `closed`" in report
    assert "## Investigation hypotheses" in report
    assert "causality is unconfirmed" in report
    for state in trace.states:
        assert f"`{state.value}`" in report


def test_human_report_on_a_halted_case_states_the_reason(
    happy_deps: CaseDependencies,
    brokered_actions_factory: Callable[[ApprovalDecision], BrokeredDefenderActions],
) -> None:
    deps = dataclasses.replace(
        happy_deps,
        brokered_actions=brokered_actions_factory(ApprovalDecision.DENIED),
    )
    trace = run_case("AGE-0001", deps)
    report = render_human_report(trace)
    assert "halted at `escalated`" in report
    assert "containment action denied by broker policy" in report
    assert "approval is absent, pending, or denied" in report
