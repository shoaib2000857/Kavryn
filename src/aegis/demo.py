"""Model-free, in-memory simulation of authorization, verification, and rollback.

This is an SDK example, not a cyber-defense test or a sandbox security claim.
Operator approvals and postcondition probes are explicitly simulated.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aegis.broker.adapter import AdapterDescriptor, AdapterLimits, AdapterPermissions, AdapterResult
from aegis.broker.broker import ActionBroker
from aegis.broker.mock import MockAdapter
from aegis.broker.registry import AdapterRegistry
from aegis.core.actions import (
    ActionDefinition,
    ActionResources,
    ActionSideEffect,
    VerificationContract,
)
from aegis.core.coordinator import (
    ActionTransactionCoordinator,
    VerificationCheck,
    VerificationOutcome,
)
from aegis.core.receipt import ExecutionReceipt
from aegis.core.transaction import ActionTransaction
from aegis.domain import (
    ActionsPolicy,
    Authorization,
    Budgets,
    Case,
    FilesystemPolicy,
    NetworkPolicy,
    ScopePolicy,
    ServiceTarget,
    Targets,
    ToolsPolicy,
)
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole
from aegis.domain.policy import RiskTier
from aegis.evidence.audit import InMemoryAuditSink
from aegis.evidence.store import InMemoryArtifactStore, sha256_digest
from aegis.policy.approval import Approval, ApprovalDecision


def run_transaction_demo(*, fail_verification: bool = False) -> ExecutionReceipt:
    """Exercise real broker/transaction logic over simulated service state."""
    now = datetime.now(UTC)
    state = {"contained": False}
    descriptor = AdapterDescriptor(
        id="demo.service",
        version=1,
        category="in-memory-simulation",
        permissions=AdapterPermissions(filesystem="none"),
        risk_tier=RiskTier.R3_REVERSIBLE_RESPONSE,
        limits=AdapterLimits(timeout_seconds=1, cpu=1, memory_mb=64),
        parser="demo-v1",
    )
    definition = ActionDefinition(
        action_type="contain.rate_limit",
        version=1,
        adapter_id=descriptor.id,
        description="Change only simulated in-memory service state.",
        risk_tier=RiskTier.R3_REVERSIBLE_RESPONSE,
        filesystem="none",
        side_effects=(ActionSideEffect.WRITE,),
        reversible=True,
        rollback_action_type="contain.rollback",
        resources=ActionResources(timeout_seconds=1, cpu=1, memory_mb=64),
        verification=VerificationContract(required=True, verifier_id="verifier:demo"),
    )
    rollback_definition = definition.model_copy(
        update={
            "action_type": "contain.rollback",
            "reversible": False,
            "rollback_action_type": None,
        }
    )

    class SimulatedServiceAdapter(MockAdapter):
        def run(self, request: ActionRequest, *, capability_ref: str) -> AdapterResult:
            result = super().run(request, capability_ref=capability_ref)
            state["contained"] = request.action_type == "contain.rate_limit"
            return result

    registry = AdapterRegistry()
    registry.register(
        SimulatedServiceAdapter(
            descriptor,
            action_definitions=(definition, rollback_definition),
        )
    )
    broker = ActionBroker(
        registry=registry,
        audit=InMemoryAuditSink(),
        artifacts=InMemoryArtifactStore(),
    )
    scope = ScopePolicy(
        case_id="AGE-0001",
        version=1,
        authorization=Authorization(expires_at=now + timedelta(minutes=10)),
        targets=Targets(services=(ServiceTarget(id="demo-service", network="demo-only"),)),
        network=NetworkPolicy(),
        filesystem=FilesystemPolicy(),
        tools=ToolsPolicy(allow=(descriptor.id,)),
        actions=ActionsPolicy(approval=(definition.action_type, rollback_definition.action_type)),
        budgets=Budgets(tool_calls=4, model_tokens=1, wall_time_seconds=60, spend_usd=1),
    )
    case = Case(
        id=scope.case_id,
        title="Simulated transaction SDK example",
        created_at=now,
        created_by="operator:demo",
        scope_ref="scope://AGE-0001/1",
        scope_digest=sha256_digest(scope.model_dump_json().encode()),
    )
    request = ActionRequest(
        id="demo-apply",
        case_id=case.id,
        actor_id="reasoning_runtime:demo",
        role=ActorRole.REASONING_RUNTIME,
        action_type=definition.action_type,
        target_ref="service://demo-service",
        adapter=descriptor.id,
        parameters={},
        reason="Operator requested an in-memory simulation, not production containment.",
        requested_at=now,
    )
    rollback = request.model_copy(
        update={
            "id": "demo-rollback",
            "action_type": rollback_definition.action_type,
        }
    )

    def approve(action: ActionRequest) -> Approval:
        return Approval(
            id=f"approval-{action.id}",
            case_id=case.id,
            subject_ref=f"action-request://{case.id}/{action.id}",
            requested_at=now,
            expires_at=now + timedelta(minutes=5),
            decision=ApprovalDecision.APPROVED,
            decided_by="operator:demo",
            decided_at=now,
        )

    def verify(tx: ActionTransaction, _result: AdapterResult) -> VerificationOutcome:
        restoring = tx.action_request.action_type == "contain.rollback"
        checks = (
            ("state", not state["contained"] if restoring else state["contained"]),
            ("benign-availability", restoring or not fail_verification),
        )
        return VerificationOutcome(
            verifier_id="verifier:demo",
            checked_at=now,
            checks=tuple(
                VerificationCheck(
                    id=name,
                    verifier_id="verifier:demo",
                    passed=passed,
                    evidence_ref=f"evidence://{case.id}/{tx.id}/{name}",
                    detail="Simulated in-memory probe; not an actual network/security measurement.",
                )
                for name, passed in checks
            ),
        )

    _, receipt, _ = ActionTransactionCoordinator(broker).execute(
        request,
        case=case,
        scope=scope,
        now=now,
        policy_version="demo-v1",
        approval=approve(request),
        verifier=verify,
        rollback_request=rollback,
        rollback_approval=approve(rollback),
        rollback_verifier=verify,
    )
    if receipt is None:
        raise RuntimeError("demo did not produce a terminal receipt")
    return receipt
