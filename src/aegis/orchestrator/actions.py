"""Broker-backed cyber response actions for the reference orchestrator.

This module is the cyber-specific bridge between model proposals and the
domain-neutral transaction coordinator. The proposal selects only the
registered action/target/adapter; operation parameters are fixed here and
then checked by scope policy and the typed adapter. It never executes a
command or mutates a target directly.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from aegis.broker.adapter import AdapterResult
from aegis.core.coordinator import (
    ActionTransactionCoordinator,
    VerificationCheck,
    VerificationOutcome,
)
from aegis.core.receipt import ExecutionReceipt
from aegis.core.transaction import ActionTransaction
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole, AwareDatetime
from aegis.domain.case import Case
from aegis.domain.scope import ScopePolicy
from aegis.policy.approval import Approval, ApprovalDecision
from aegis.providers.schemas import ProposedAction
from aegis.repair.candidate import PatchCandidate

__all__ = ["BrokeredContainmentResult", "BrokeredDefenderActions"]

ApprovalProvider = Callable[[ActionRequest], Approval | None]
Probe = Callable[[], bool]
Clock = Callable[[], AwareDatetime]


@dataclass(frozen=True)
class BrokeredContainmentResult:
    transaction: ActionTransaction
    receipt: ExecutionReceipt | None
    verification: VerificationOutcome | None


class BrokeredDefenderActions:
    """Submit fixed containment/rollback operations via policy and broker."""

    def __init__(
        self,
        *,
        coordinator: ActionTransactionCoordinator,
        case: Case,
        scope: ScopePolicy,
        approval_provider: ApprovalProvider,
        policy_version: str,
        clock: Clock = lambda: datetime.now(UTC),
    ) -> None:
        if case.id != scope.case_id:
            raise ValueError("case and scope identifiers must match")
        self._coordinator = coordinator
        self._case = case
        self._scope = scope
        self._approval_provider = approval_provider
        self._policy_version = policy_version
        self._clock = clock

    def contain(
        self,
        proposal: ProposedAction,
        *,
        exploit_reachable: Probe,
        attack_blocked: Probe,
        benign_available: Probe,
    ) -> BrokeredContainmentResult:
        """Apply a fixed traversal filter, verify it, and roll back on failure.

        The model may not provide action parameters for this operation. The
        action catalog, not the model, chooses ``operation=apply`` and its
        corresponding typed rollback request.
        """
        if proposal.parameters:
            raise ValueError("containment proposal parameters are not configurable")
        now = self._clock()
        request = ActionRequest(
            id=f"contain-{uuid4().hex}",
            case_id=self._case.id,
            actor_id="reasoning_runtime:v1",
            role=ActorRole.REASONING_RUNTIME,
            action_type=proposal.action_type,
            target_ref=proposal.target_ref,
            adapter=proposal.adapter,
            parameters={"operation": "apply"},
            expected_evidence=("attack_blocked", "benign_available"),
            reason=proposal.reason,
            requested_at=now,
        )
        rollback_request = ActionRequest(
            id=f"rollback-{uuid4().hex}",
            case_id=self._case.id,
            actor_id="control:transaction-coordinator",
            role=ActorRole.CONTROL_PLANE,
            action_type="contain.rollback",
            target_ref=proposal.target_ref,
            adapter=proposal.adapter,
            parameters={"operation": "rollback", "rollback_of": request.id},
            expected_evidence=("rollback_restored",),
            reason="Restore the prior containment policy after failed verification.",
            requested_at=now,
        )
        approval = self._approval_provider(request)

        def verify_containment(
            transaction: ActionTransaction, _result: AdapterResult
        ) -> VerificationOutcome:
            return self._verification(
                transaction,
                (
                    ("attack-blocked", attack_blocked(), "observed attack replay is blocked"),
                    ("benign-available", benign_available(), "benign request remains available"),
                ),
                checked_at=self._clock(),
            )

        def verify_rollback(
            transaction: ActionTransaction, _result: AdapterResult
        ) -> VerificationOutcome:
            return self._verification(
                transaction,
                (
                    (
                        "rollback-restored-attack",
                        exploit_reachable(),
                        "prior attack behavior restored",
                    ),
                    (
                        "rollback-restored-benign",
                        benign_available(),
                        "benign request remains available",
                    ),
                ),
                checked_at=self._clock(),
            )

        transaction, receipt, verification = self._coordinator.execute(
            request,
            case=self._case,
            scope=self._scope,
            now=now,
            policy_version=self._policy_version,
            approval=approval,
            verifier=verify_containment,
            rollback_request=rollback_request,
            rollback_approval=(
                self._approval_provider(rollback_request)
                if approval is not None and approval.decision is ApprovalDecision.APPROVED
                else None
            ),
            rollback_verifier=verify_rollback,
        )
        return BrokeredContainmentResult(transaction, receipt, verification)

    def deploy(
        self,
        candidate: PatchCandidate,
        *,
        target_ref: str,
        attack_blocked: Probe,
        benign_available: Probe,
    ) -> BrokeredContainmentResult:
        """Build and roll out a verified candidate through one R4 transaction.

        The fixed registered adapter owns the Docker operations. The request
        carries only the content-addressed candidate diff and base digest; it
        cannot select an image, container, Docker argument, or network.
        """
        if candidate.case_id != self._case.id:
            raise ValueError("candidate belongs to a different case")
        now = self._clock()
        request = ActionRequest(
            id=f"deploy-{uuid4().hex}",
            case_id=self._case.id,
            actor_id="control:transaction-coordinator",
            role=ActorRole.CONTROL_PLANE,
            action_type="deployment.rollout",
            target_ref=target_ref,
            adapter="range.deployment",
            parameters={
                "operation": "apply",
                "candidate_diff": candidate.diff,
                "diff_digest": candidate.diff_digest.digest,
                "base_source_digest": candidate.base_source_digest.digest,
            },
            expected_evidence=("attack_blocked", "benign_available"),
            reason="Roll out the independently verified candidate in the authorized range.",
            requested_at=now,
        )
        rollback_request = ActionRequest(
            id=f"deployment-rollback-{uuid4().hex}",
            case_id=self._case.id,
            actor_id="control:transaction-coordinator",
            role=ActorRole.CONTROL_PLANE,
            action_type="deployment.rollback",
            target_ref=target_ref,
            adapter="range.deployment",
            parameters={"operation": "rollback", "rollback_of": request.id},
            expected_evidence=("attack_blocked", "benign_available"),
            reason="Restore the prior range image and containment rule after failed verification.",
            requested_at=now,
        )
        approval = self._approval_provider(request)

        def verify_deployment(
            transaction: ActionTransaction, _result: AdapterResult
        ) -> VerificationOutcome:
            return self._verification(
                transaction,
                (
                    ("attack-blocked", attack_blocked(), "patched service blocks traversal replay"),
                    ("benign-available", benign_available(), "benign request remains available"),
                ),
                checked_at=self._clock(),
            )

        def verify_rollback(
            transaction: ActionTransaction, _result: AdapterResult
        ) -> VerificationOutcome:
            return self._verification(
                transaction,
                (
                    (
                        "rollback-attack-blocked",
                        attack_blocked(),
                        "prior containment remains active",
                    ),
                    (
                        "rollback-benign-available",
                        benign_available(),
                        "prior service remains available",
                    ),
                ),
                checked_at=self._clock(),
            )

        transaction, receipt, verification = self._coordinator.execute(
            request,
            case=self._case,
            scope=self._scope,
            now=now,
            policy_version=self._policy_version,
            approval=approval,
            verifier=verify_deployment,
            rollback_request=rollback_request,
            rollback_approval=(
                self._approval_provider(rollback_request)
                if approval is not None and approval.decision is ApprovalDecision.APPROVED
                else None
            ),
            rollback_verifier=verify_rollback,
        )
        return BrokeredContainmentResult(transaction, receipt, verification)

    @staticmethod
    def _verification(
        transaction: ActionTransaction,
        checks: tuple[tuple[str, bool, str], ...],
        *,
        checked_at: AwareDatetime,
    ) -> VerificationOutcome:
        verifier_id = "verifier:range-probes"
        return VerificationOutcome(
            verifier_id=verifier_id,
            checked_at=checked_at,
            checks=tuple(
                VerificationCheck(
                    id=check_id,
                    verifier_id=verifier_id,
                    passed=passed,
                    evidence_ref=(f"evidence://{transaction.case_id}/{transaction.id}/{check_id}"),
                    detail=detail,
                )
                for check_id, passed, detail in checks
            ),
        )
