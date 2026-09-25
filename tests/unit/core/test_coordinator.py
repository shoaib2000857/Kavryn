from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest

from aegis.broker.adapter import AdapterDescriptor, AdapterLimits, AdapterPermissions, AdapterResult
from aegis.broker.broker import ActionBroker
from aegis.broker.mock import MockAdapter
from aegis.broker.registry import AdapterRegistry
from aegis.core.actions import (
    ActionDefinition,
    ActionParameter,
    ActionResources,
    ActionSideEffect,
    ActionValueType,
    VerificationContract,
)
from aegis.core.coordinator import (
    ActionTransactionCoordinator,
    VerificationCheck,
    VerificationFunction,
    VerificationOutcome,
    Verifier,
)
from aegis.core.receipt import ExecutionDisposition, verify_execution_receipt
from aegis.core.transaction import ActionTransaction, TransactionState
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole
from aegis.domain.case import Case
from aegis.domain.policy import RiskTier
from aegis.domain.scope import ScopePolicy
from aegis.evidence.audit import InMemoryAuditSink
from aegis.evidence.store import InMemoryArtifactStore
from aegis.policy.approval import Approval, ApprovalDecision


@pytest.fixture
def broker() -> ActionBroker:
    descriptor = AdapterDescriptor(
        id="semgrep.scan",
        version=1,
        category="synthetic-test-adapter",
        permissions=AdapterPermissions(filesystem="read-target"),
        risk_tier=RiskTier.R1_ANALYZE,
        limits=AdapterLimits(timeout_seconds=30, cpu=1, memory_mb=256),
        parser="test-v1",
    )
    registry = AdapterRegistry()
    action_definition = ActionDefinition(
        action_type="deployment.rollout",
        version=1,
        adapter_id="semgrep.scan",
        description="Synthetic transaction-coordinator test action.",
        inputs=(
            ActionParameter(
                name="ruleset_ref",
                value_type=ActionValueType.STRING,
                description="Test input reference.",
            ),
        ),
        risk_tier=RiskTier.R4_CHANGE,
        side_effects=(ActionSideEffect.WRITE,),
        filesystem="read-target",
        resources=ActionResources(timeout_seconds=30, cpu=1, memory_mb=256),
        verification=VerificationContract(required=True, verifier_id="verifier:independent"),
    )
    scan_definition = action_definition.model_copy(
        update={
            "action_type": "scan.run",
            "description": "Synthetic scan action used by coordinator tests.",
            "risk_tier": RiskTier.R1_ANALYZE,
        }
    )
    registry.register(
        MockAdapter(
            descriptor,
            allowed_parameter_keys=frozenset({"ruleset_ref"}),
            action_definitions=(action_definition, scan_definition),
        )
    )
    return ActionBroker(
        registry=registry,
        audit=InMemoryAuditSink(),
        artifacts=InMemoryArtifactStore(),
    )


def _request(now: datetime, **updates: Any) -> ActionRequest:
    fields: dict[str, Any] = {
        "id": "tx-request-1",
        "case_id": "AGE-0001",
        "actor_id": "reasoning_runtime:v1",
        "role": ActorRole.REASONING_RUNTIME,
        "action_type": "deployment.rollout",
        "target_ref": "workspace://AGE-0001/candidate/x",
        "adapter": "semgrep.scan",
        "parameters": {"ruleset_ref": "immutable-artifact://rules/python"},
        "reason": "Apply an authorized synthetic-range change.",
        "requested_at": now,
    }
    fields.update(updates)
    return ActionRequest(**fields)


def _approval(request: ActionRequest, now: datetime, *, name: str = "approval-1") -> Approval:
    return Approval(
        id=name,
        case_id=request.case_id,
        subject_ref=f"action-request://{request.case_id}/{request.id}",
        requested_at=now,
        expires_at=now + timedelta(minutes=5),
        decision=ApprovalDecision.APPROVED,
        decided_by="operator:alice",
        decided_at=now,
    )


def _verifier(passed: bool) -> VerificationFunction:
    def verify(tx: ActionTransaction, _result: AdapterResult) -> VerificationOutcome:
        return VerificationOutcome(
            verifier_id="verifier:independent",
            checked_at=tx.created_at,
            checks=(
                VerificationCheck(
                    id="postcondition-1",
                    verifier_id="verifier:independent",
                    passed=passed,
                    evidence_ref=f"evidence://{tx.case_id}/{tx.id}/postcondition-1",
                    detail="synthetic postcondition probe",
                ),
            ),
        )

    return verify


def test_object_verifier_protocol_is_used_with_trusted_check_timestamp(
    broker: ActionBroker, case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    class IndependentVerifier:
        def verify(
            self,
            transaction: ActionTransaction,
            result: AdapterResult,
            *,
            checked_at: datetime,
        ) -> VerificationOutcome:
            return _verifier(True)(transaction, result).model_copy(
                update={"checked_at": checked_at}
            )

    request = _request(now)
    verifier: Verifier = IndependentVerifier()
    tx, _, verification = ActionTransactionCoordinator(broker).execute(
        request,
        case=case,
        scope=scope_policy,
        now=now,
        policy_version="scope-v1",
        approval=_approval(request, now),
        verifier=verifier,
    )

    assert tx.state is TransactionState.COMMITTED
    assert verification is not None and verification.checked_at == now


def test_approval_verified_action_commits_and_emits_audit_linked_receipt(
    broker: ActionBroker, case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    request = _request(now)
    tx, receipt, verification = ActionTransactionCoordinator(broker).execute(
        request,
        case=case,
        scope=scope_policy,
        now=now,
        policy_version="scope-v1",
        approval=_approval(request, now),
        verifier=_verifier(True),
    )

    assert tx.state is TransactionState.COMMITTED
    assert [transition.to_state for transition in tx.transitions] == [
        TransactionState.POLICY_CHECKED,
        TransactionState.AWAITING_APPROVAL,
        TransactionState.AUTHORIZED,
        TransactionState.CAPABILITY_ISSUED,
        TransactionState.EXECUTING,
        TransactionState.EXECUTED,
        TransactionState.VERIFYING,
        TransactionState.VERIFIED,
        TransactionState.COMMITTED,
    ]
    assert verification is not None and verification.passed
    assert receipt is not None and receipt.disposition is ExecutionDisposition.COMMITTED
    assert receipt.audit_root == broker.audit_root(case.id)
    assert verify_execution_receipt(receipt)


def test_failed_postcondition_broker_executes_and_verifies_rollback(
    broker: ActionBroker, case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    request = _request(now, action_type="scan.run")
    rollback = _request(
        now,
        id="tx-rollback-1",
        action_type="deployment.rollout",
        reason="Restore prior synthetic range state.",
    )
    tx, receipt, verification = ActionTransactionCoordinator(broker).execute(
        request,
        case=case,
        scope=scope_policy,
        now=now,
        policy_version="scope-v1",
        verifier=_verifier(False),
        rollback_request=rollback,
        rollback_approval=_approval(rollback, now, name="approval-rollback-1"),
        rollback_verifier=_verifier(True),
    )

    assert tx.state is TransactionState.ROLLED_BACK
    assert tx.rollback_ref == f"transaction://{case.id}/tx-rollback-1-rollback"
    assert verification is not None and not verification.passed
    assert receipt is not None and receipt.disposition is ExecutionDisposition.ROLLED_BACK
    assert receipt.audit_root == broker.audit_root(case.id)
    assert verify_execution_receipt(receipt)


def test_failed_postcondition_without_rollback_escalates_not_commits(
    broker: ActionBroker, case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    request = _request(now, action_type="scan.run")
    tx, receipt, verification = ActionTransactionCoordinator(broker).execute(
        request,
        case=case,
        scope=scope_policy,
        now=now,
        policy_version="scope-v1",
        verifier=_verifier(False),
    )

    assert tx.state is TransactionState.ESCALATED
    assert receipt is not None and receipt.disposition is ExecutionDisposition.ESCALATED
    assert verification is not None and not verification.passed


def test_verifier_exception_fails_closed_and_runs_rollback(
    broker: ActionBroker, case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    request = _request(now, action_type="scan.run")
    rollback = _request(now, id="tx-rollback-error", action_type="deployment.rollout")

    def broken_verifier(_tx: ActionTransaction, _result: AdapterResult) -> VerificationOutcome:
        raise RuntimeError("verifier test failure")

    tx, receipt, verification = ActionTransactionCoordinator(broker).execute(
        request,
        case=case,
        scope=scope_policy,
        now=now,
        policy_version="scope-v1",
        verifier=broken_verifier,
        rollback_request=rollback,
        rollback_approval=_approval(rollback, now, name="approval-rollback-error"),
        rollback_verifier=_verifier(True),
    )

    assert tx.state is TransactionState.ROLLED_BACK
    assert verification is not None and not verification.passed
    assert "fail closed" in verification.checks[0].detail
    assert receipt is not None and receipt.disposition is ExecutionDisposition.ROLLED_BACK


def test_unregistered_verifier_identity_cannot_satisfy_action_contract(
    broker: ActionBroker, case: Case, scope_policy: ScopePolicy, now: datetime
) -> None:
    request = _request(now)
    rollback = _request(now, id="tx-rollback-wrong-verifier")

    def wrong_identity(tx: ActionTransaction, result: AdapterResult) -> VerificationOutcome:
        valid = _verifier(True)(tx, result)
        return valid.model_copy(
            update={
                "verifier_id": "verifier:impostor",
                "checks": tuple(
                    check.model_copy(update={"verifier_id": "verifier:impostor"})
                    for check in valid.checks
                ),
            }
        )

    tx, receipt, outcome = ActionTransactionCoordinator(broker).execute(
        request,
        case=case,
        scope=scope_policy,
        now=now,
        policy_version="scope-v1",
        approval=_approval(request, now),
        verifier=wrong_identity,
        rollback_request=rollback,
        rollback_approval=_approval(rollback, now, name="approval-wrong-verifier-rollback"),
        rollback_verifier=_verifier(True),
    )

    assert tx.state is TransactionState.ROLLED_BACK
    assert outcome is not None and not outcome.passed
    assert "fail closed" in outcome.checks[0].detail
    assert receipt is not None and receipt.disposition is ExecutionDisposition.ROLLED_BACK
