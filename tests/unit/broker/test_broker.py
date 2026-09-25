from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

import pytest

from aegis.broker.adapter import ParameterValidationError
from aegis.broker.broker import ActionBroker, BrokerError
from aegis.broker.registry import AdapterRegistry
from aegis.domain.action import ActionRequest
from aegis.domain.audit import AuditEventType
from aegis.domain.case import Case
from aegis.domain.policy import PolicyOutcome
from aegis.domain.scope import Budgets, ScopePolicy
from aegis.evidence.audit import InMemoryAuditSink
from aegis.evidence.store import InMemoryArtifactStore


@pytest.fixture
def broker(
    registry: AdapterRegistry, audit_sink: InMemoryAuditSink, artifact_store: InMemoryArtifactStore
) -> ActionBroker:
    return ActionBroker(registry=registry, audit=audit_sink, artifacts=artifact_store)


def test_permitted_request_runs_the_adapter_and_records_three_audit_events(
    broker: ActionBroker,
    case: Case,
    scope_policy: ScopePolicy,
    now: datetime,
    audit_sink: InMemoryAuditSink,
    make_request: Callable[..., ActionRequest],
) -> None:
    outcome = broker.submit(
        make_request(now),
        case=case,
        scope=scope_policy,
        now=now,
        decision_id="dec-0001",
        policy_version="scope-v1",
    )
    assert outcome.decision.outcome is PolicyOutcome.PERMITTED
    assert outcome.result is not None
    assert outcome.result.exit_status == "success"

    events = audit_sink.events_for_case(case.id)
    assert [e.event_type for e in events] == [
        AuditEventType.ACTION_REQUESTED,
        AuditEventType.POLICY_DECISION_RECORDED,
        AuditEventType.TOOL_RUN_RECORDED,
    ]
    # Hash-chain linkage, in order.
    assert events[1].prev_event_digest == events[0].integrity
    assert events[2].prev_event_digest == events[1].integrity


def test_permitted_request_increments_tool_call_usage(
    broker: ActionBroker,
    case: Case,
    scope_policy: ScopePolicy,
    now: datetime,
    make_request: Callable[..., ActionRequest],
) -> None:
    assert broker.usage_for(case.id).tool_calls == 0
    broker.submit(
        make_request(now),
        case=case,
        scope=scope_policy,
        now=now,
        decision_id="dec-0001",
        policy_version="scope-v1",
    )
    assert broker.usage_for(case.id).tool_calls == 1


def test_denied_request_never_runs_the_adapter(
    broker: ActionBroker,
    case: Case,
    scope_policy: ScopePolicy,
    now: datetime,
    audit_sink: InMemoryAuditSink,
    make_request: Callable[..., ActionRequest],
) -> None:
    """The out-of-scope-path acceptance-constraint case, exercised
    end-to-end through the broker rather than the pure decision function."""
    request = make_request(now, target_ref="workspace://AGE-0001/somewhere-else/x")
    outcome = broker.submit(
        request,
        case=case,
        scope=scope_policy,
        now=now,
        decision_id="dec-0001",
        policy_version="scope-v1",
    )
    assert outcome.decision.outcome is PolicyOutcome.DENIED
    assert outcome.result is None
    events = audit_sink.events_for_case(case.id)
    assert [e.event_type for e in events] == [
        AuditEventType.ACTION_REQUESTED,
        AuditEventType.POLICY_DECISION_RECORDED,
    ]
    assert broker.usage_for(case.id).tool_calls == 0


def test_approval_required_request_never_runs_the_adapter(
    broker: ActionBroker,
    case: Case,
    scope_policy: ScopePolicy,
    now: datetime,
    make_request: Callable[..., ActionRequest],
) -> None:
    request = make_request(
        now,
        action_type="deployment.rollout",
        target_ref="workspace://AGE-0001/candidate/x",
    )
    outcome = broker.submit(
        request,
        case=case,
        scope=scope_policy,
        now=now,
        decision_id="dec-0001",
        policy_version="scope-v1",
    )
    assert outcome.decision.outcome is PolicyOutcome.APPROVAL_REQUIRED
    assert outcome.result is None
    assert broker.usage_for(case.id).tool_calls == 0


def test_scope_permitted_but_unregistered_adapter_raises_broker_error(
    registry: AdapterRegistry,
    audit_sink: InMemoryAuditSink,
    artifact_store: InMemoryArtifactStore,
    case: Case,
    scope_policy: ScopePolicy,
    now: datetime,
    make_request: Callable[..., ActionRequest],
) -> None:
    """A scope policy allow-listing an adapter that was never registered
    with this broker is a control-plane configuration fault, not an
    ordinary denial — it must be surfaced loudly."""
    broker = ActionBroker(registry=registry, audit=audit_sink, artifacts=artifact_store)
    request = make_request(now, action_type="test.run", adapter="pytest.run")
    with pytest.raises(BrokerError):
        broker.submit(
            request,
            case=case,
            scope=scope_policy,
            now=now,
            decision_id="dec-0001",
            policy_version="scope-v1",
        )


def test_repeated_action_budget_exhaustion_denies_further_actions(
    broker: ActionBroker,
    case: Case,
    scope_policy: ScopePolicy,
    now: datetime,
    make_request: Callable[..., ActionRequest],
) -> None:
    tight_scope = scope_policy.model_copy(
        update={
            "budgets": Budgets(
                tool_calls=2, model_tokens=100_000, wall_time_seconds=3600, spend_usd=20
            )
        }
    )
    for i in range(2):
        outcome = broker.submit(
            make_request(now, id=f"req-{i}"),
            case=case,
            scope=tight_scope,
            now=now,
            decision_id=f"dec-{i}",
            policy_version="scope-v1",
        )
        assert outcome.decision.outcome is PolicyOutcome.PERMITTED

    third = broker.submit(
        make_request(now, id="req-2"),
        case=case,
        scope=tight_scope,
        now=now,
        decision_id="dec-2",
        policy_version="scope-v1",
    )
    assert third.decision.outcome is PolicyOutcome.DENIED
    assert "budget exhausted" in third.decision.reasons[0]
    assert broker.usage_for(case.id).tool_calls == 2  # unchanged by the denied 3rd request


def test_timeout_result_is_recorded_not_raised(
    registry: AdapterRegistry,
    audit_sink: InMemoryAuditSink,
    artifact_store: InMemoryArtifactStore,
    case: Case,
    scope_policy: ScopePolicy,
    now: datetime,
    make_request: Callable[..., ActionRequest],
) -> None:
    """A completed tool call does not imply a successful defensive
    outcome (docs/WORKFLOWS.md); a timeout is ordinary auditable data."""
    scan_adapter = registry.get("semgrep.scan")
    scan_adapter._simulate_timeout = True  # type: ignore[attr-defined]
    broker = ActionBroker(registry=registry, audit=audit_sink, artifacts=artifact_store)
    outcome = broker.submit(
        make_request(now),
        case=case,
        scope=scope_policy,
        now=now,
        decision_id="dec-0001",
        policy_version="scope-v1",
    )
    assert outcome.decision.outcome is PolicyOutcome.PERMITTED
    assert outcome.result is not None
    assert outcome.result.exit_status == "timeout"
    events = audit_sink.events_for_case(case.id)
    assert events[-1].event_type is AuditEventType.TOOL_RUN_RECORDED
    assert "timeout" in events[-1].summary


def test_unrecognized_parameter_raises_before_a_tool_run_event_is_recorded(
    broker: ActionBroker,
    case: Case,
    scope_policy: ScopePolicy,
    now: datetime,
    audit_sink: InMemoryAuditSink,
    make_request: Callable[..., ActionRequest],
) -> None:
    request = make_request(now, parameters={"unexpected_flag": "--dangerous"})
    with pytest.raises(ParameterValidationError):
        broker.submit(
            request,
            case=case,
            scope=scope_policy,
            now=now,
            decision_id="dec-0001",
            policy_version="scope-v1",
        )
    events = audit_sink.events_for_case(case.id)
    assert [e.event_type for e in events] == [
        AuditEventType.ACTION_REQUESTED,
        AuditEventType.POLICY_DECISION_RECORDED,
    ]


def test_expired_scope_is_denied_before_any_tool_dispatch(
    broker: ActionBroker,
    case: Case,
    scope_policy: ScopePolicy,
    now: datetime,
    make_request: Callable[..., ActionRequest],
) -> None:
    outcome = broker.submit(
        make_request(now),
        case=case,
        scope=scope_policy,
        now=now + timedelta(days=30),
        decision_id="dec-0001",
        policy_version="scope-v1",
    )
    assert outcome.decision.outcome is PolicyOutcome.DENIED
    assert outcome.result is None
