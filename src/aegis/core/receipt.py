"""Versioned, content-hashed records for completed action transactions."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Final, Literal, Protocol

from pydantic import Field

from aegis.core.transaction import ActionTransaction, TransactionState
from aegis.domain.base import (
    ActionId,
    ActorId,
    AegisModel,
    AwareDatetime,
    CaseId,
    Digest,
    RecordId,
    ToolId,
    Uri,
)

__all__ = [
    "EXECUTION_RECEIPT_SCHEMA_VERSION",
    "ExecutionDisposition",
    "ExecutionReceipt",
    "ReceiptStore",
    "create_execution_receipt",
    "receipt_from_transaction",
    "verify_execution_receipt",
]


class ReceiptStore(Protocol):
    """Operator-owned durable receipt sink; persistence grants no authority."""

    def put_receipt(self, receipt: ExecutionReceipt) -> None: ...

    def receipt_for_transaction(self, transaction_id: str) -> ExecutionReceipt | None: ...


EXECUTION_RECEIPT_SCHEMA_VERSION: Final[Literal["aegis.execution_receipt/v1"]] = (
    "aegis.execution_receipt/v1"
)


class ExecutionDisposition(StrEnum):
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    DENIED = "denied"
    ESCALATED = "escalated"
    CONTROL_FAILURE = "control_failure"


class ExecutionReceipt(AegisModel):
    """Portable statement of what a transaction attempted and verified."""

    schema_version: Literal["aegis.execution_receipt/v1"] = EXECUTION_RECEIPT_SCHEMA_VERSION
    id: RecordId
    transaction_id: RecordId
    case_id: CaseId
    actor_id: ActorId
    model_provider: Annotated[str | None, Field(max_length=128)] = None
    model_id: Annotated[str | None, Field(max_length=128)] = None
    action_type: ActionId
    adapter: ToolId
    target_ref: Uri
    scope_digest: Digest
    policy_version: Annotated[str, Field(min_length=1, max_length=128)]
    capability_ref: Uri | None = None
    environment_ref: Uri | None = None
    input_artifacts: tuple[Digest, ...] = ()
    output_artifacts: tuple[Digest, ...] = ()
    evidence_refs: tuple[Uri, ...] = ()
    verification_refs: tuple[Uri, ...] = ()
    disposition: ExecutionDisposition
    rollback_ref: Uri | None = None
    audit_root: Digest | None = None
    issued_at: AwareDatetime
    integrity: Digest


def _canonical_payload(receipt: ExecutionReceipt) -> bytes:
    data = receipt.model_dump(mode="json", exclude={"integrity"})
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def create_execution_receipt(receipt: ExecutionReceipt) -> ExecutionReceipt:
    """Return a copy of ``receipt`` sealed with its stable SHA-256 digest."""
    provisional = receipt.model_copy(update={"integrity": Digest(digest="0" * 64)})
    digest = hashlib.sha256(_canonical_payload(provisional)).hexdigest()
    return provisional.model_copy(update={"integrity": Digest(digest=digest)})


def receipt_from_transaction(
    transaction: ActionTransaction,
    *,
    disposition: ExecutionDisposition,
    issued_at: AwareDatetime,
    audit_root: Digest,
    model_provider: str | None = None,
    model_id: str | None = None,
) -> ExecutionReceipt:
    """Build a sealed receipt from a terminal transaction snapshot.

    `EXECUTED` and `VERIFIED` are intentionally not receipt dispositions:
    a caller cannot describe an action as committed until the transaction
    has crossed the corresponding terminal state.
    """
    expected_state = {
        ExecutionDisposition.COMMITTED: TransactionState.COMMITTED,
        ExecutionDisposition.ROLLED_BACK: TransactionState.ROLLED_BACK,
        ExecutionDisposition.DENIED: TransactionState.DENIED,
        ExecutionDisposition.ESCALATED: TransactionState.ESCALATED,
        ExecutionDisposition.CONTROL_FAILURE: TransactionState.CONTROL_FAILURE,
    }[disposition]
    if transaction.state is not expected_state:
        raise ValueError(
            f"receipt disposition {disposition.value} requires transaction state "
            f"{expected_state.value}, got {transaction.state.value}"
        )
    request = transaction.action_request
    receipt = ExecutionReceipt(
        id=f"receipt-{transaction.id}",
        transaction_id=transaction.id,
        case_id=transaction.case_id,
        actor_id=request.actor_id,
        model_provider=model_provider,
        model_id=model_id,
        action_type=request.action_type,
        adapter=request.adapter,
        target_ref=request.target_ref,
        scope_digest=transaction.scope_digest,
        policy_version=transaction.policy_version,
        capability_ref=transaction.capability_ref,
        environment_ref=transaction.environment_ref,
        input_artifacts=transaction.input_artifacts,
        output_artifacts=transaction.output_artifacts,
        evidence_refs=transaction.evidence_refs,
        verification_refs=transaction.verification_refs,
        disposition=disposition,
        rollback_ref=transaction.rollback_ref,
        audit_root=audit_root,
        issued_at=issued_at,
        integrity=Digest(digest="0" * 64),
    )
    return create_execution_receipt(receipt)


def verify_execution_receipt(receipt: ExecutionReceipt) -> bool:
    expected = hashlib.sha256(_canonical_payload(receipt)).hexdigest()
    return receipt.integrity.digest == expected
