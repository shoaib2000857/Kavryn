from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from aegis.broker.adapter import AdapterResult
from aegis.broker.broker import ActionBroker, BrokerError
from aegis.broker.mock import MockAdapter
from aegis.broker.registry import AdapterRegistry
from aegis.core.actions import ActionParameter, ActionValueType, VerificationContract
from aegis.core.coordinator import (
    ActionTransactionCoordinator,
    VerificationCheck,
    VerificationOutcome,
)
from aegis.core.receipt import ExecutionDisposition, verify_execution_receipt
from aegis.core.transaction import ActionTransaction, TransactionState
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole
from aegis.domain.case import Case
from aegis.domain.scope import ActionsPolicy, ScopePolicy
from aegis.evidence.audit import verify_audit_chain
from aegis.evidence.sqlite_store import SQLiteEvidenceStore
from aegis.policy.approval import Approval, ApprovalDecision


def _registry(scan_adapter: MockAdapter) -> tuple[AdapterRegistry, MockAdapter]:
    parent = scan_adapter.action_definitions[1].model_copy(
        update={
            "reversible": True,
            "rollback_action_type": "deployment.rollback",
            "verification": VerificationContract(required=True, verifier_id="verifier:recovery"),
        }
    )
    rollback = parent.model_copy(
        update={
            "action_type": "deployment.rollback",
            "reversible": False,
            "rollback_action_type": None,
            "inputs": (
                *parent.inputs,
                ActionParameter(
                    name="rollback_of",
                    value_type=ActionValueType.STRING,
                    description="Exact original action request identifier.",
                ),
            ),
        }
    )
    adapter = MockAdapter(
        scan_adapter.descriptor,
        allowed_parameter_keys=frozenset({"ruleset_ref", "rollback_of"}),
        action_definitions=(parent, rollback),
    )
    registry = AdapterRegistry()
    registry.register(adapter)
    return registry, adapter


def _approval(request: ActionRequest, now: datetime) -> Approval:
    return Approval(
        id=f"approval-{request.id}",
        case_id=request.case_id,
        subject_ref=f"action-request://{request.case_id}/{request.id}",
        requested_at=now,
        expires_at=now + timedelta(minutes=5),
        decision=ApprovalDecision.APPROVED,
        decided_by="operator:alice",
        decided_at=now,
    )


def _scope(scope: ScopePolicy) -> ScopePolicy:
    return scope.model_copy(
        update={
            "actions": ActionsPolicy(
                approval=("deployment.rollout", "deployment.rollback"), deny=("host.shell",)
            )
        }
    )


def _verify(
    passed: bool, now: datetime
) -> Callable[[ActionTransaction, AdapterResult], VerificationOutcome]:
    def verify(tx: ActionTransaction, _result: AdapterResult) -> VerificationOutcome:
        return VerificationOutcome(
            verifier_id="verifier:recovery",
            checked_at=now,
            checks=(
                VerificationCheck(
                    id="postcondition",
                    verifier_id="verifier:recovery",
                    passed=passed,
                    evidence_ref=f"evidence://{tx.case_id}/{tx.id}/postcondition",
                    detail="Independent test observation of target state.",
                ),
            ),
        )

    return verify


@pytest.mark.parametrize("rollback_passes", (True, False))
def test_journaled_coordinator_allows_exact_rollback_and_preserves_failure_quarantine(
    tmp_path: Path,
    scan_adapter: MockAdapter,
    make_request: Callable[..., ActionRequest],
    case: Case,
    scope_policy: ScopePolicy,
    now: datetime,
    rollback_passes: bool,
) -> None:
    registry, adapter = _registry(scan_adapter)
    request = make_request(now, action_type="deployment.rollout")
    rollback = make_request(
        now,
        id="request-rollback",
        action_type="deployment.rollback",
        actor_id="control:transaction-coordinator",
        role=ActorRole.CONTROL_PLANE,
        parameters={**request.parameters, "rollback_of": request.id},
    )
    path = tmp_path / "runtime.sqlite3"
    with SQLiteEvidenceStore(path) as store:
        broker = ActionBroker(registry=registry, audit=store, artifacts=store, journal=store)
        tx, receipt, outcome = ActionTransactionCoordinator(broker).execute(
            request,
            case=case,
            scope=_scope(scope_policy),
            now=now,
            policy_version="scope-v1",
            approval=_approval(request, now),
            verifier=_verify(False, now),
            rollback_request=rollback,
            rollback_approval=_approval(rollback, now),
            rollback_verifier=_verify(rollback_passes, now),
        )
        assert adapter.calls == [request, rollback]
        assert outcome is not None and not outcome.passed
        assert receipt is not None and verify_execution_receipt(receipt)
        assert receipt.disposition is (
            ExecutionDisposition.ROLLED_BACK
            if rollback_passes
            else ExecutionDisposition.CONTROL_FAILURE
        )
        assert store.transaction_for_id(tx.id) == tx
        assert verify_audit_chain(store.events_for_case(case.id))

    with SQLiteEvidenceStore(path) as reopened:
        restarted = ActionBroker(
            registry=registry, audit=reopened, artifacts=reopened, journal=reopened
        )
        assert restarted.usage_for(case.id).tool_calls == 2
        assert bool(restarted.unresolved_effects_for_case(case.id)) is not rollback_passes


@pytest.mark.parametrize(
    "invalid",
    ("actor", "target", "action", "parent", "stale", "restart", "missing-approval"),
)
def test_quarantine_rollback_exemption_cannot_authorize_unrelated_actions(
    tmp_path: Path,
    scan_adapter: MockAdapter,
    make_request: Callable[..., ActionRequest],
    case: Case,
    scope_policy: ScopePolicy,
    now: datetime,
    invalid: str,
) -> None:
    registry, adapter = _registry(scan_adapter)
    request = make_request(now, action_type="deployment.rollout")
    scope = _scope(scope_policy)
    with SQLiteEvidenceStore(tmp_path / "runtime.sqlite3") as store:
        broker = ActionBroker(registry=registry, audit=store, artifacts=store, journal=store)
        pending = broker.submit(
            request,
            case=case,
            scope=scope,
            now=now,
            decision_id="decision-pending",
            policy_version="scope-v1",
        )
        executed = broker.submit(
            request,
            case=case,
            scope=scope,
            now=now,
            decision_id="decision-execute",
            policy_version="scope-v1",
            approval=_approval(request, now),
            prior_transaction=pending.transaction,
        )
        tx = executed.transaction
        for state in (
            TransactionState.VERIFYING,
            TransactionState.FAILED,
            TransactionState.ROLLING_BACK,
        ):
            tx = broker.advance_transaction(tx, state, now=now, reason="test recovery lifecycle")
        assert len(adapter.calls) == 1
        rollback = make_request(
            now,
            id="request-rollback",
            action_type="deployment.rollback",
            actor_id="control:transaction-coordinator",
            role=ActorRole.CONTROL_PLANE,
            parameters={**request.parameters, "rollback_of": request.id},
        )
        if invalid == "actor":
            rollback = rollback.model_copy(update={"role": ActorRole.REASONING_RUNTIME})
        elif invalid == "target":
            rollback = rollback.model_copy(update={"target_ref": "service://other"})
        elif invalid == "action":
            rollback = rollback.model_copy(update={"action_type": "deployment.rollout"})
        elif invalid == "parent":
            rollback = rollback.model_copy(
                update={"parameters": {**request.parameters, "rollback_of": "other"}}
            )
        elif invalid == "restart":
            broker = ActionBroker(registry=registry, audit=store, artifacts=store, journal=store)
        elif invalid == "stale":
            tx = executed.transaction
        if invalid == "missing-approval":
            outcome = broker.submit(
                rollback,
                case=case,
                scope=scope,
                now=now,
                decision_id="decision-rollback",
                policy_version="scope-v1",
                rollback_for=tx,
            )
            assert outcome.transaction.state is TransactionState.AWAITING_APPROVAL
            assert outcome.result is None
            assert len(adapter.calls) == 1
            assert broker.unresolved_effects_for_case(case.id)
            return
        with pytest.raises(BrokerError, match="unresolved journaled mutation"):
            broker.submit(
                rollback,
                case=case,
                scope=scope,
                now=now,
                decision_id="decision-rollback",
                policy_version="scope-v1",
                approval=_approval(rollback, now),
                rollback_for=tx,
            )
        assert len(adapter.calls) == 1
        assert broker.unresolved_effects_for_case(case.id)


def test_blocked_coordinator_rollback_returns_control_failure_receipt(
    tmp_path: Path,
    scan_adapter: MockAdapter,
    make_request: Callable[..., ActionRequest],
    case: Case,
    scope_policy: ScopePolicy,
    now: datetime,
) -> None:
    registry, adapter = _registry(scan_adapter)
    request = make_request(now, action_type="deployment.rollout")
    invalid_rollback = make_request(
        now,
        id="invalid-rollback",
        action_type="deployment.rollback",
        parameters={**request.parameters, "rollback_of": request.id},
        role=ActorRole.REASONING_RUNTIME,
    )
    with SQLiteEvidenceStore(tmp_path / "runtime.sqlite3") as store:
        broker = ActionBroker(registry=registry, audit=store, artifacts=store, journal=store)
        tx, receipt, outcome = ActionTransactionCoordinator(broker).execute(
            request,
            case=case,
            scope=_scope(scope_policy),
            now=now,
            policy_version="scope-v1",
            approval=_approval(request, now),
            verifier=_verify(False, now),
            rollback_request=invalid_rollback,
            rollback_approval=_approval(invalid_rollback, now),
            rollback_verifier=_verify(True, now),
        )
        assert adapter.calls == [request]
        assert tx.state is TransactionState.CONTROL_FAILURE
        assert outcome is not None and not outcome.passed
        assert receipt is not None and receipt.disposition is ExecutionDisposition.CONTROL_FAILURE
        assert verify_execution_receipt(receipt)
        assert broker.unresolved_effects_for_case(case.id) == (tx,)
