"""The action broker: the only effectful path from a request to a tool.

See docs/PRODUCT_REQUIREMENTS.md SR-AUT-004 ("The action broker is the
only effectful path from reasoning to tools or targets") and
docs/ARCHITECTURE.md's data-flow steps 6-9: resolve policy, dispatch to
a worker, audit request/decision/result.

``ActionBroker.submit`` is the integration point for Changes 1-4: it
evaluates the pure policy decision (Change 2) against a request (Change
1), dispatches to a registered typed adapter (Change 4) only if
permitted, and records every request, decision, and result to the
append-only audit sink and content-addressed artifact store (Change 2).
It never lets an unregistered adapter or unresolved capability through
silently.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from itertools import count
from threading import RLock

from aegis.broker.adapter import AdapterResult, ParameterValidationError, validate_parameters
from aegis.broker.registry import AdapterRegistry, UnknownAdapterError
from aegis.core.actions import ActionDefinition
from aegis.core.capability import Capability, CapabilityAuthority, capability_parameters_digest
from aegis.core.transaction import ActionTransaction, TransactionState
from aegis.domain.action import ActionRequest
from aegis.domain.audit import AuditEvent, AuditEventType
from aegis.domain.base import ActorRole, AegisModel, AwareDatetime, CaseId, Digest
from aegis.domain.case import Case
from aegis.domain.policy import PolicyDecision, PolicyOutcome
from aegis.domain.scope import ScopePolicy
from aegis.evidence.audit import AuditSink, audit_event_digest
from aegis.evidence.store import ArtifactStore
from aegis.monitoring.behavioral import (
    BehavioralAssessment,
    BehavioralMonitor,
    BehavioralObservation,
)
from aegis.policy.approval import Approval
from aegis.policy.budget import BudgetUsage
from aegis.policy.decision import evaluate_action_request

__all__ = ["ActionBroker", "BrokerError", "BrokerOutcome"]


class BrokerError(RuntimeError):
    """Raised on a broker-level integrity failure (not an ordinary policy denial).

    E.g. a scope policy allow-lists an adapter id that was never
    registered: the request must not silently proceed or silently
    degrade to "denied" as if the operator had intended that — it is a
    configuration/control fault that must be surfaced loudly.
    """


class BrokerOutcome(AegisModel):
    decision: PolicyDecision
    result: AdapterResult | None = None
    capability: Capability | None = None
    transaction: ActionTransaction
    monitoring: BehavioralAssessment | None = None


class ActionBroker:
    def __init__(
        self,
        *,
        registry: AdapterRegistry,
        audit: AuditSink,
        artifacts: ArtifactStore,
        capabilities: CapabilityAuthority | None = None,
        capability_ttl_seconds: int = 60,
        behavioral_monitor: BehavioralMonitor | None = None,
    ) -> None:
        if capability_ttl_seconds <= 0:
            raise ValueError("capability_ttl_seconds must be positive")
        self._registry = registry
        self._audit = audit
        self._artifacts = artifacts
        self._capabilities = capabilities or CapabilityAuthority()
        self._behavioral_monitor = behavioral_monitor or BehavioralMonitor()
        self._capability_ttl = timedelta(seconds=capability_ttl_seconds)
        self._usage: dict[str, BudgetUsage] = {}
        self._audit_seq = count(1)
        self._transactions: dict[str, ActionTransaction] = {}
        self._transaction_lock = RLock()

    def usage_for(self, case_id: CaseId) -> BudgetUsage:
        return self._usage.get(case_id, BudgetUsage())

    def advance_transaction(
        self,
        transaction: ActionTransaction,
        next_state: TransactionState,
        *,
        now: AwareDatetime,
        reason: str,
    ) -> ActionTransaction:
        """Apply and audit a verifier/control-plane transaction transition."""
        with self._transaction_lock:
            stored = self._transactions.get(transaction.id)
            if not self._same_transaction_snapshot(stored, transaction):
                raise BrokerError("transaction snapshot is stale or was not issued by this broker")
            updated = transaction.transition_to(next_state, at=now, reason=reason)
            self._append_audit(
                case_id=transaction.case_id,
                now=now,
                event_type=AuditEventType.TRANSACTION_TRANSITION_RECORDED,
                actor_id="control:transaction-coordinator",
                role=ActorRole.CONTROL_PLANE,
                subject_ref=f"transaction://{transaction.case_id}/{transaction.id}",
                summary=f"{transaction.state.value}->{next_state.value}: {reason[:300]}",
            )
            self._transactions[transaction.id] = updated
        return updated

    @staticmethod
    def _same_transaction_snapshot(
        stored: ActionTransaction | None, candidate: ActionTransaction
    ) -> bool:
        """Compare broker-owned lifecycle fields, allowing attached evidence refs."""
        return bool(
            stored is not None
            and stored.case_id == candidate.case_id
            and stored.action_request == candidate.action_request
            and stored.scope_digest == candidate.scope_digest
            and stored.policy_version == candidate.policy_version
            and stored.state is candidate.state
            and stored.transitions == candidate.transitions
        )

    def audit_root(self, case_id: CaseId) -> Digest | None:
        """Return the current case audit-chain head for receipt linking."""
        event = self._audit.last_event(case_id)
        return event.integrity if event is not None else None

    def action_definition(self, action_type: str) -> ActionDefinition:
        """Return the immutable catalog definition used to govern this action."""
        try:
            return self._registry.action_definition(action_type)
        except KeyError as exc:
            raise BrokerError(f"action definition is not registered: {action_type}") from exc

    def record_evidence_artifact(
        self,
        *,
        case_id: CaseId,
        content: bytes,
        now: AwareDatetime,
        producer: str,
    ) -> str:
        """Persist immutable evidence and audit its content-addressed reference."""
        digest = self._artifacts.put(content)
        artifact_ref = f"artifact://{case_id}/sha256/{digest.digest}"
        self._append_audit(
            case_id=case_id,
            now=now,
            event_type=AuditEventType.EVIDENCE_RECORDED,
            actor_id=producer,
            role=ActorRole.CONTROL_PLANE,
            subject_ref=artifact_ref,
            summary=f"content-addressed evidence stored: sha256:{digest.digest}",
        )
        return artifact_ref

    def submit(
        self,
        request: ActionRequest,
        *,
        case: Case,
        scope: ScopePolicy,
        now: datetime,
        decision_id: str,
        policy_version: str,
        transaction_id: str | None = None,
        approval: Approval | None = None,
        prior_transaction: ActionTransaction | None = None,
    ) -> BrokerOutcome:
        usage = self.usage_for(case.id)
        candidate_capability_ref = f"capability://{case.id}/{decision_id}"
        bound_transaction_id = transaction_id or (
            prior_transaction.id if prior_transaction is not None else request.id
        )
        with self._transaction_lock:
            if prior_transaction is not None:
                stored = self._transactions.get(bound_transaction_id)
                if (
                    prior_transaction.state is not TransactionState.AWAITING_APPROVAL
                    or prior_transaction.case_id != case.id
                    or prior_transaction.id != bound_transaction_id
                    or prior_transaction.action_request != request
                    or prior_transaction.scope_digest != case.scope_digest
                    or prior_transaction.policy_version != policy_version
                    or not self._same_transaction_snapshot(stored, prior_transaction)
                ):
                    raise BrokerError(
                        "prior transaction is not a matching approval-pending transaction"
                    )
                transaction = prior_transaction
                if approval is not None:
                    transaction = transaction.model_copy(
                        update={"approval_ref": f"approval://{case.id}/{approval.id}"}
                    )
            else:
                if bound_transaction_id in self._transactions:
                    raise BrokerError("transaction identifier has already been used")
                transaction = ActionTransaction(
                    id=bound_transaction_id,
                    case_id=case.id,
                    action_request=request,
                    scope_digest=case.scope_digest,
                    policy_version=policy_version,
                    created_at=now,
                    updated_at=now,
                    approval_ref=f"approval://{case.id}/{approval.id}"
                    if approval is not None
                    else None,
                )
                self._transactions[bound_transaction_id] = transaction

        def advance(next_state: TransactionState, reason: str) -> None:
            nonlocal transaction
            with self._transaction_lock:
                stored = self._transactions.get(bound_transaction_id)
                if not self._same_transaction_snapshot(stored, transaction):
                    raise BrokerError("transaction snapshot is stale during broker execution")
                previous_state = transaction.state
                updated = transaction.transition_to(next_state, at=now, reason=reason)
                self._append_audit(
                    case_id=case.id,
                    now=now,
                    event_type=AuditEventType.TRANSACTION_TRANSITION_RECORDED,
                    actor_id="control:action-broker",
                    role=ActorRole.CONTROL_PLANE,
                    subject_ref=f"transaction://{case.id}/{bound_transaction_id}",
                    summary=(f"{previous_state.value}->{next_state.value}: {reason[:300]}"),
                )
                transaction = updated
                self._transactions[bound_transaction_id] = transaction

        decision = evaluate_action_request(
            request,
            case=case,
            scope=scope,
            usage=usage,
            now=now,
            decision_id=decision_id,
            policy_version=policy_version,
            capability_ref=candidate_capability_ref,
            approval=approval,
        )
        monitoring = self._behavioral_monitor.observe(
            BehavioralObservation(
                request_id=request.id,
                case_id=case.id,
                actor_id=request.actor_id,
                action_type=request.action_type,
                outcome=decision.outcome,
                risk_tier=decision.risk_tier,
            )
        )
        if prior_transaction is None:
            advance(TransactionState.POLICY_CHECKED, "deterministic policy evaluated")

        self._append_audit(
            case_id=case.id,
            now=now,
            event_type=AuditEventType.ACTION_REQUESTED,
            actor_id=request.actor_id,
            role=request.role,
            subject_ref=f"action-request://{case.id}/{request.id}",
            summary=f"action_type={request.action_type} adapter={request.adapter}",
        )
        self._append_audit(
            case_id=case.id,
            now=now,
            event_type=AuditEventType.POLICY_DECISION_RECORDED,
            actor_id="control-plane:policy-engine",
            role=ActorRole.CONTROL_PLANE,
            subject_ref=f"policy-decision://{case.id}/{decision.id}",
            summary=f"outcome={decision.outcome.value} risk_tier={decision.risk_tier.value}",
        )
        if approval is not None:
            self._append_audit(
                case_id=case.id,
                now=now,
                event_type=AuditEventType.APPROVAL_RECORDED,
                actor_id=approval.decided_by or "control:approval-service",
                role=ActorRole.CONTROL_PLANE,
                subject_ref=f"approval://{case.id}/{approval.id}",
                summary=(
                    f"decision={approval.decision or 'pending'} "
                    f"request={request.id} expires_at={approval.expires_at.isoformat()}"
                ),
            )

        if decision.outcome is not PolicyOutcome.PERMITTED:
            if decision.outcome is PolicyOutcome.DENIED:
                advance(TransactionState.DENIED, decision.reasons[0])
            elif transaction.state is TransactionState.POLICY_CHECKED:
                advance(TransactionState.AWAITING_APPROVAL, decision.reasons[0])
            return BrokerOutcome(
                decision=decision,
                result=None,
                transaction=transaction,
                monitoring=monitoring,
            )

        assert decision.capability_ref is not None  # guaranteed by PolicyDecision's own invariant

        try:
            adapter = self._registry.get(request.adapter)
        except UnknownAdapterError as exc:
            advance(TransactionState.ESCALATED, "permitted action has no registered adapter")
            raise BrokerError(
                f"scope permitted adapter '{request.adapter}' but it is not registered"
            ) from exc

        try:
            action_definition = self._registry.validate_request(request)
        except KeyError as exc:
            advance(TransactionState.ESCALATED, "action type has no registered definition")
            raise BrokerError(f"action definition rejected request: {exc}") from exc
        except ValueError as exc:
            advance(TransactionState.DENIED, "request did not satisfy its action definition")
            raise ParameterValidationError(str(exc)) from exc
        if action_definition.risk_tier is not decision.risk_tier:
            advance(TransactionState.ESCALATED, "action definition and policy risk disagree")
            raise BrokerError("action definition risk tier differs from deterministic policy")

        # Reject malformed requests before issuing authority or extending
        # the audit trail with a capability that could never execute.
        validate_parameters(
            request.adapter,
            request.parameters,
            allowed_keys=adapter.allowed_parameter_keys,
        )

        advance(TransactionState.AUTHORIZED, "scope policy permitted the action")

        capability = self._capabilities.issue(
            Capability(
                id=f"cap-{decision_id}",
                issuer="control:action-broker",
                subject=request.actor_id,
                case_id=request.case_id,
                transaction_id=bound_transaction_id,
                scope_digest=case.scope_digest,
                action_type=request.action_type,
                adapter=request.adapter,
                target_ref=request.target_ref,
                risk_tier=decision.risk_tier,
                parameters_digest=capability_parameters_digest(request.parameters),
                issued_at=now,
                expires_at=now + self._capability_ttl,
                single_use=True,
                max_uses=1,
            )
        )
        transaction = transaction.model_copy(update={"capability_ref": decision.capability_ref})
        advance(TransactionState.CAPABILITY_ISSUED, "narrow one-use capability issued")
        self._append_audit(
            case_id=case.id,
            now=now,
            event_type=AuditEventType.CAPABILITY_ISSUED,
            actor_id="control:action-broker",
            role=ActorRole.CONTROL_PLANE,
            subject_ref=decision.capability_ref,
            summary=(
                f"transaction_id={bound_transaction_id} action_type={request.action_type} "
                f"adapter={request.adapter} expires_at={capability.expires_at.isoformat()}"
            ),
        )
        self._capabilities.consume(
            capability.id,
            request,
            transaction_id=bound_transaction_id,
            now=now,
        )

        advance(TransactionState.EXECUTING, "typed adapter execution started")
        result = adapter.run(request, capability_ref=decision.capability_ref)
        if result.exit_status == "success":
            try:
                self._registry.validate_output(action_definition, result.output)
            except ValueError as exc:
                advance(TransactionState.CONTROL_FAILURE, "adapter output violated action contract")
                raise BrokerError(f"adapter output violated action contract: {exc}") from exc
        transaction = transaction.model_copy(update={"output_artifacts": ()})

        result_digest = self._artifacts.put(result.model_dump_json().encode())
        transaction = transaction.model_copy(update={"output_artifacts": (result_digest,)})
        if result.exit_status == "success":
            advance(
                TransactionState.EXECUTED,
                "adapter returned successfully; postconditions pending",
            )
        else:
            advance(TransactionState.FAILED, f"adapter returned {result.exit_status}")
        self._append_audit(
            case_id=case.id,
            now=now,
            event_type=AuditEventType.TOOL_RUN_RECORDED,
            actor_id=f"worker:{request.adapter}",
            role=ActorRole.WORKER,
            subject_ref=f"tool-run://{case.id}/{request.id}",
            summary=(
                f"adapter={request.adapter} exit_status={result.exit_status} "
                f"result_digest=sha256:{result_digest.digest}"
            ),
        )

        self._usage[case.id] = usage.model_copy(update={"tool_calls": usage.tool_calls + 1})

        return BrokerOutcome(
            decision=decision,
            result=result,
            capability=capability,
            transaction=transaction,
            monitoring=monitoring,
        )

    def _append_audit(
        self,
        *,
        case_id: str,
        now: datetime,
        event_type: AuditEventType,
        actor_id: str,
        role: ActorRole,
        subject_ref: str,
        summary: str,
    ) -> None:
        event_id = f"audit-{case_id}-{next(self._audit_seq)}"
        prior = self._audit.last_event(case_id)
        event = AuditEvent(
            id=event_id,
            case_id=case_id,
            created_at=now,
            event_type=event_type,
            actor_id=actor_id,
            role=role,
            subject_ref=subject_ref,
            summary=summary,
            integrity=Digest(digest="0" * 64),
            prev_event_digest=prior.integrity if prior else None,
        )
        event = event.model_copy(update={"integrity": audit_event_digest(event)})
        self._audit.append(event)
