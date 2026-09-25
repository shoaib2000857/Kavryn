"""Verifier-gated coordinator for brokered consequential actions.

The coordinator does not choose actions or construct commands. It submits
typed requests through ``ActionBroker`` and commits only after an independent
verifier returns evidence-bearing checks. Failed postconditions either cause a
brokered rollback followed by independent rollback verification, or an explicit
escalation/control-failure receipt.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Final, Literal, Protocol, runtime_checkable
from uuid import uuid4

from pydantic import Field, model_validator

from aegis.broker.adapter import AdapterResult
from aegis.broker.broker import ActionBroker, BrokerOutcome
from aegis.core.receipt import (
    ExecutionDisposition,
    ExecutionReceipt,
    receipt_from_transaction,
)
from aegis.core.transaction import ActionTransaction, TransactionState
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorId, AegisModel, AwareDatetime, Uri
from aegis.domain.case import Case
from aegis.domain.scope import ScopePolicy
from aegis.policy.approval import Approval

__all__ = [
    "ActionTransactionCoordinator",
    "VerificationCheck",
    "VerificationFunction",
    "VerificationOutcome",
    "Verifier",
    "VerifierLike",
]

VERIFICATION_OUTCOME_SCHEMA_VERSION: Final[Literal["aegis.verification_outcome/v1"]] = (
    "aegis.verification_outcome/v1"
)


class VerificationCheck(AegisModel):
    """One independently produced postcondition check with evidence provenance."""

    id: str = Field(min_length=1, max_length=128)
    verifier_id: ActorId
    passed: bool
    evidence_ref: Uri
    detail: str = Field(min_length=1, max_length=1000)


class VerificationOutcome(AegisModel):
    """The complete verifier result for one action transaction."""

    schema_version: Literal["aegis.verification_outcome/v1"] = VERIFICATION_OUTCOME_SCHEMA_VERSION
    verifier_id: ActorId
    checked_at: AwareDatetime
    checks: tuple[VerificationCheck, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _checks_are_consistent(self) -> VerificationOutcome:
        if len({check.id for check in self.checks}) != len(self.checks):
            raise ValueError("verification check identifiers must be unique")
        if any(check.verifier_id != self.verifier_id for check in self.checks):
            raise ValueError("all checks must be attributed to the declared verifier")
        return self

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)


@runtime_checkable
class Verifier(Protocol):
    """Independent typed verifier for one executed transaction."""

    def verify(
        self,
        transaction: ActionTransaction,
        result: AdapterResult,
        *,
        checked_at: AwareDatetime,
    ) -> VerificationOutcome: ...


VerificationFunction = Callable[[ActionTransaction, AdapterResult], VerificationOutcome]
VerifierLike = Verifier | VerificationFunction


class ActionTransactionCoordinator:
    """Run one typed action with approval, independent verification, and receipts."""

    def __init__(self, broker: ActionBroker) -> None:
        self._broker = broker

    def execute(
        self,
        request: ActionRequest,
        *,
        case: Case,
        scope: ScopePolicy,
        now: datetime,
        policy_version: str,
        verifier: VerifierLike,
        approval: Approval | None = None,
        rollback_request: ActionRequest | None = None,
        rollback_approval: Approval | None = None,
        rollback_verifier: VerifierLike | None = None,
        model_provider: str | None = None,
        model_id: str | None = None,
    ) -> tuple[ActionTransaction, ExecutionReceipt | None, VerificationOutcome | None]:
        """Execute, verify, then commit or roll back; always fail closed.

        Approval-gated requests are first submitted without approval so the
        broker records ``AWAITING_APPROVAL``. A supplied approval resumes that
        exact transaction, after which policy is re-evaluated before a
        capability is issued.
        """
        first = self._submit(
            request,
            case=case,
            scope=scope,
            now=now,
            policy_version=policy_version,
            transaction_id=request.id,
            approval=None,
        )
        current = first
        if first.transaction.state is TransactionState.AWAITING_APPROVAL:
            if approval is None:
                return first.transaction, None, None
            current = self._submit(
                request,
                case=case,
                scope=scope,
                now=now,
                policy_version=policy_version,
                transaction_id=first.transaction.id,
                approval=approval,
                prior_transaction=first.transaction,
            )

        tx = current.transaction
        if current.result is None:
            disposition = self._terminal_disposition(tx.state)
            if disposition is None:
                return tx, None, None
            return tx, self._receipt(tx, disposition, now, model_provider, model_id), None

        if current.result.exit_status != "success":
            error_detail = current.result.output.get("error")
            failure_reason = "adapter execution failed"
            if isinstance(error_detail, str) and error_detail:
                failure_reason = f"adapter execution failed: {error_detail[:500]}"
            tx = self._advance(tx, TransactionState.CONTROL_FAILURE, now, failure_reason)
            receipt = self._receipt(
                tx, ExecutionDisposition.CONTROL_FAILURE, now, model_provider, model_id
            )
            return tx, receipt, None

        tx = self._advance(tx, TransactionState.VERIFYING, now, "independent verification started")
        definition = self._broker.action_definition(request.action_type)
        outcome = self._verify(
            verifier,
            tx,
            current.result,
            request.actor_id,
            now=now,
            expected_verifier_id=definition.verification.verifier_id,
        )
        tx = self._attach_verification(tx, outcome, now=now)
        if outcome.passed:
            tx = self._advance(tx, TransactionState.VERIFIED, now, "all required checks passed")
            tx = self._advance(
                tx, TransactionState.COMMITTED, now, "verified postconditions committed"
            )
            receipt = self._receipt(
                tx, ExecutionDisposition.COMMITTED, now, model_provider, model_id
            )
            return tx, receipt, outcome

        tx = self._advance(tx, TransactionState.FAILED, now, "one or more postconditions failed")
        if rollback_request is None or rollback_verifier is None:
            tx = self._advance(tx, TransactionState.ESCALATED, now, "rollback unavailable")
            receipt = self._receipt(
                tx, ExecutionDisposition.ESCALATED, now, model_provider, model_id
            )
            return tx, receipt, outcome

        tx = self._advance(tx, TransactionState.ROLLING_BACK, now, "starting brokered rollback")
        rollback_tx = self._broker_rollback(
            rollback_request,
            case=case,
            scope=scope,
            now=now,
            policy_version=policy_version,
            approval=rollback_approval,
        )
        if rollback_tx.result is None or rollback_tx.result.exit_status != "success":
            tx = self._advance(
                tx,
                TransactionState.CONTROL_FAILURE,
                now,
                "rollback was denied, incomplete, or failed",
            )
            receipt = self._receipt(
                tx, ExecutionDisposition.CONTROL_FAILURE, now, model_provider, model_id
            )
            return tx, receipt, outcome

        rollback_state = self._advance(
            rollback_tx.transaction,
            TransactionState.VERIFYING,
            now,
            "independent rollback verification started",
        )
        rollback_outcome = self._verify(
            rollback_verifier,
            rollback_state,
            rollback_tx.result,
            rollback_request.actor_id,
            now=now,
            expected_verifier_id=self._broker.action_definition(
                rollback_request.action_type
            ).verification.verifier_id,
        )
        rollback_state = self._attach_verification(rollback_state, rollback_outcome, now=now)
        if not rollback_outcome.passed:
            self._advance(
                rollback_state,
                TransactionState.CONTROL_FAILURE,
                now,
                "rollback postconditions failed",
            )
            tx = tx.model_copy(
                update={"rollback_ref": f"transaction://{case.id}/{rollback_state.id}"}
            )
            tx = self._advance(
                tx, TransactionState.CONTROL_FAILURE, now, "rollback verification failed"
            )
            receipt = self._receipt(
                tx, ExecutionDisposition.CONTROL_FAILURE, now, model_provider, model_id
            )
            return tx, receipt, outcome

        rollback_state = self._advance(
            rollback_state, TransactionState.VERIFIED, now, "rollback postconditions verified"
        )
        self._advance(rollback_state, TransactionState.COMMITTED, now, "rollback action committed")
        tx = tx.model_copy(
            update={
                "rollback_ref": f"transaction://{case.id}/{rollback_state.id}",
                "evidence_refs": (*tx.evidence_refs, *rollback_state.evidence_refs),
                "verification_refs": (
                    *tx.verification_refs,
                    *rollback_state.verification_refs,
                ),
            }
        )
        tx = self._advance(tx, TransactionState.ROLLED_BACK, now, "rollback independently verified")
        receipt = self._receipt(tx, ExecutionDisposition.ROLLED_BACK, now, model_provider, model_id)
        return tx, receipt, outcome

    def _submit(
        self,
        request: ActionRequest,
        *,
        case: Case,
        scope: ScopePolicy,
        now: datetime,
        policy_version: str,
        transaction_id: str,
        approval: Approval | None,
        prior_transaction: ActionTransaction | None = None,
    ) -> BrokerOutcome:
        return self._broker.submit(
            request,
            case=case,
            scope=scope,
            now=now,
            decision_id=f"decision-{uuid4().hex}",
            policy_version=policy_version,
            transaction_id=transaction_id,
            approval=approval,
            prior_transaction=prior_transaction,
        )

    def _broker_rollback(
        self,
        request: ActionRequest,
        *,
        case: Case,
        scope: ScopePolicy,
        now: datetime,
        policy_version: str,
        approval: Approval | None,
    ) -> BrokerOutcome:
        first = self._submit(
            request,
            case=case,
            scope=scope,
            now=now,
            policy_version=policy_version,
            transaction_id=f"{request.id}-rollback",
            approval=None,
        )
        if first.transaction.state is not TransactionState.AWAITING_APPROVAL or approval is None:
            return first
        return self._submit(
            request,
            case=case,
            scope=scope,
            now=now,
            policy_version=policy_version,
            transaction_id=first.transaction.id,
            approval=approval,
            prior_transaction=first.transaction,
        )

    def _advance(
        self,
        tx: ActionTransaction,
        state: TransactionState,
        now: datetime,
        reason: str,
    ) -> ActionTransaction:
        return self._broker.advance_transaction(tx, state, now=now, reason=reason)

    @staticmethod
    def _verify(
        verifier: VerifierLike,
        tx: ActionTransaction,
        result: AdapterResult,
        actor_id: ActorId,
        *,
        now: AwareDatetime,
        expected_verifier_id: ActorId | None,
    ) -> VerificationOutcome:
        try:
            if isinstance(verifier, Verifier):
                outcome = verifier.verify(tx, result, checked_at=now)
            else:
                outcome = verifier(tx, result)
            if expected_verifier_id is not None and outcome.verifier_id != expected_verifier_id:
                raise ValueError("verification producer does not match action contract")
            if outcome.verifier_id == actor_id or any(
                check.verifier_id == actor_id for check in outcome.checks
            ):
                raise ValueError("action actor cannot author its own verification evidence")
            if any(check.verifier_id != outcome.verifier_id for check in outcome.checks):
                raise ValueError("check producer does not match verification outcome producer")
            return outcome
        except Exception as exc:
            supervisor = "control:verifier-supervisor"
            return VerificationOutcome(
                verifier_id=supervisor,
                checked_at=now,
                checks=(
                    VerificationCheck(
                        id=f"verifier-error-{tx.id}",
                        verifier_id=supervisor,
                        passed=False,
                        evidence_ref=f"evidence://{tx.case_id}/verifier-error/{tx.id}",
                        detail=f"verification unavailable ({type(exc).__name__}); fail closed",
                    ),
                ),
            )

    @staticmethod
    def _verification_refs(outcome: VerificationOutcome) -> tuple[Uri, ...]:
        return tuple(check.evidence_ref for check in outcome.checks)

    def _attach_verification(
        self, tx: ActionTransaction, outcome: VerificationOutcome, *, now: datetime
    ) -> ActionTransaction:
        artifact_ref = self._broker.record_evidence_artifact(
            case_id=tx.case_id,
            content=outcome.model_dump_json().encode(),
            now=now,
            producer=outcome.verifier_id,
        )
        verification_refs = (*self._verification_refs(outcome), artifact_ref)
        return tx.model_copy(
            update={
                "evidence_refs": (*tx.evidence_refs, artifact_ref),
                "verification_refs": (*tx.verification_refs, *verification_refs),
            }
        )

    def _receipt(
        self,
        tx: ActionTransaction,
        disposition: ExecutionDisposition,
        now: datetime,
        model_provider: str | None,
        model_id: str | None,
    ) -> ExecutionReceipt:
        audit_root = self._broker.audit_root(tx.case_id)
        if audit_root is None:
            raise RuntimeError("cannot issue execution receipt without an audit chain")
        return receipt_from_transaction(
            tx,
            disposition=disposition,
            issued_at=now,
            audit_root=audit_root,
            model_provider=model_provider,
            model_id=model_id,
        )

    @staticmethod
    def _terminal_disposition(state: TransactionState) -> ExecutionDisposition | None:
        if state is TransactionState.DENIED:
            return ExecutionDisposition.DENIED
        if state is TransactionState.ESCALATED:
            return ExecutionDisposition.ESCALATED
        if state is TransactionState.CONTROL_FAILURE:
            return ExecutionDisposition.CONTROL_FAILURE
        return None
