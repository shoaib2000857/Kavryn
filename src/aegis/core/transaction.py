"""Immutable action-transaction records and their legal state machine."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Final, Literal

from pydantic import Field, model_validator

from aegis.domain.action import ActionRequest
from aegis.domain.base import AegisModel, AwareDatetime, CaseId, Digest, Reason, RecordId, Uri

__all__ = [
    "ACTION_TRANSACTION_SCHEMA_VERSION",
    "ActionTransaction",
    "IllegalTransactionTransitionError",
    "TransactionState",
    "TransactionTransition",
]

ACTION_TRANSACTION_SCHEMA_VERSION: Final[Literal["aegis.action_transaction/v1"]] = (
    "aegis.action_transaction/v1"
)


class TransactionState(StrEnum):
    PROPOSED = "proposed"
    POLICY_CHECKED = "policy_checked"
    DENIED = "denied"
    AWAITING_APPROVAL = "awaiting_approval"
    AUTHORIZED = "authorized"
    CAPABILITY_ISSUED = "capability_issued"
    STAGED = "staged"
    EXECUTING = "executing"
    EXECUTED = "executed"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    FAILED = "failed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    COMMITTED = "committed"
    ESCALATED = "escalated"
    CONTROL_FAILURE = "control_failure"


_LEGAL_TRANSITIONS: Final[dict[TransactionState, frozenset[TransactionState]]] = {
    TransactionState.PROPOSED: frozenset({TransactionState.POLICY_CHECKED}),
    TransactionState.POLICY_CHECKED: frozenset(
        {
            TransactionState.DENIED,
            TransactionState.AWAITING_APPROVAL,
            TransactionState.AUTHORIZED,
            TransactionState.ESCALATED,
        }
    ),
    TransactionState.AWAITING_APPROVAL: frozenset(
        {TransactionState.AUTHORIZED, TransactionState.DENIED, TransactionState.ESCALATED}
    ),
    TransactionState.AUTHORIZED: frozenset({TransactionState.CAPABILITY_ISSUED}),
    TransactionState.CAPABILITY_ISSUED: frozenset(
        {TransactionState.STAGED, TransactionState.EXECUTING}
    ),
    TransactionState.STAGED: frozenset({TransactionState.EXECUTING}),
    TransactionState.EXECUTING: frozenset(
        {
            TransactionState.EXECUTED,
            TransactionState.FAILED,
            TransactionState.CONTROL_FAILURE,
        }
    ),
    TransactionState.EXECUTED: frozenset({TransactionState.VERIFYING}),
    TransactionState.VERIFYING: frozenset(
        {
            TransactionState.VERIFIED,
            TransactionState.FAILED,
            TransactionState.ESCALATED,
            TransactionState.CONTROL_FAILURE,
        }
    ),
    TransactionState.VERIFIED: frozenset(
        {TransactionState.COMMITTED, TransactionState.ROLLING_BACK}
    ),
    TransactionState.FAILED: frozenset(
        {
            TransactionState.ROLLING_BACK,
            TransactionState.ESCALATED,
            TransactionState.CONTROL_FAILURE,
        }
    ),
    TransactionState.ROLLING_BACK: frozenset(
        {TransactionState.ROLLED_BACK, TransactionState.CONTROL_FAILURE}
    ),
    TransactionState.DENIED: frozenset(),
    TransactionState.ROLLED_BACK: frozenset(),
    TransactionState.COMMITTED: frozenset(),
    TransactionState.ESCALATED: frozenset(),
    TransactionState.CONTROL_FAILURE: frozenset(),
}


class IllegalTransactionTransitionError(ValueError):
    """Raised when a transaction attempts a transition absent from its state graph."""


class TransactionTransition(AegisModel):
    from_state: TransactionState
    to_state: TransactionState
    at: AwareDatetime
    reason: Reason


class ActionTransaction(AegisModel):
    """Immutable snapshot of one proposed consequential action."""

    schema_version: Literal["aegis.action_transaction/v1"] = ACTION_TRANSACTION_SCHEMA_VERSION
    id: RecordId
    case_id: CaseId
    action_request: ActionRequest
    action_definition_digest: Digest | None = None
    scope_digest: Digest
    policy_version: Annotated[str, Field(min_length=1, max_length=128)]
    state: TransactionState = TransactionState.PROPOSED
    created_at: AwareDatetime
    updated_at: AwareDatetime
    capability_ref: Uri | None = None
    approval_ref: Uri | None = None
    environment_ref: Uri | None = None
    reversible: bool = False
    input_artifacts: tuple[Digest, ...] = ()
    output_artifacts: tuple[Digest, ...] = ()
    evidence_refs: tuple[Uri, ...] = ()
    verification_refs: tuple[Uri, ...] = ()
    rollback_ref: Uri | None = None
    transitions: tuple[TransactionTransition, ...] = ()

    @model_validator(mode="after")
    def _transaction_invariants(self) -> ActionTransaction:
        if self.case_id != self.action_request.case_id:
            raise ValueError("transaction and action request case_id must match")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must be at or after created_at")
        if self.transitions:
            if self.transitions[0].from_state is not TransactionState.PROPOSED:
                raise ValueError("first transition must start from PROPOSED")
            for previous, current in zip(self.transitions, self.transitions[1:], strict=False):
                if previous.to_state is not current.from_state:
                    raise ValueError("transaction transition history is discontinuous")
            if self.transitions[-1].to_state is not self.state:
                raise ValueError("transaction state must match the last recorded transition")
        elif self.state is not TransactionState.PROPOSED:
            raise ValueError("a transaction without history must start in PROPOSED")
        return self

    def transition_to(
        self, next_state: TransactionState, *, at: AwareDatetime, reason: str
    ) -> ActionTransaction:
        """Return a new transaction after checking and recording one legal transition."""
        if next_state not in _LEGAL_TRANSITIONS[self.state]:
            raise IllegalTransactionTransitionError(
                f"illegal transaction transition: {self.state.value} -> {next_state.value}"
            )
        if at < self.updated_at:
            raise IllegalTransactionTransitionError(
                "transition timestamp precedes transaction update time"
            )
        transition = TransactionTransition(
            from_state=self.state,
            to_state=next_state,
            at=at,
            reason=reason,
        )
        return self.model_copy(
            update={
                "state": next_state,
                "updated_at": at,
                "transitions": (*self.transitions, transition),
            }
        )


def legal_transaction_targets(state: TransactionState) -> frozenset[TransactionState]:
    """Return the legal next states for inspection and CLI/documentation use."""
    return _LEGAL_TRANSITIONS[state]
