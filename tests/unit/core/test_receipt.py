from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aegis.core.receipt import (
    ExecutionDisposition,
    ExecutionReceipt,
    create_execution_receipt,
    receipt_from_transaction,
    verify_execution_receipt,
)
from aegis.core.transaction import ActionTransaction, TransactionState
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole, Digest


def _receipt() -> ExecutionReceipt:
    return ExecutionReceipt(
        id="receipt-1",
        transaction_id="tx-1",
        case_id="AGE-0001",
        actor_id="agent:test",
        model_provider="llama.cpp-compatible",
        model_id="qwen38",
        action_type="range.contain",
        adapter="range.proxy",
        target_ref="service://range/api",
        scope_digest=Digest(digest="a" * 64),
        policy_version="policy-v1",
        capability_ref="capability://cap-1",
        environment_ref="environment://range-1",
        input_artifacts=(Digest(digest="b" * 64),),
        output_artifacts=(Digest(digest="c" * 64),),
        evidence_refs=("evidence://range-1/containment",),
        verification_refs=("verification://range-1/attack-and-benign",),
        disposition=ExecutionDisposition.COMMITTED,
        audit_root=Digest(digest="d" * 64),
        issued_at=datetime(2026, 9, 25, tzinfo=UTC),
        integrity=Digest(digest="0" * 64),
    )


def test_receipt_seal_is_stable_and_verifiable() -> None:
    receipt = create_execution_receipt(_receipt())
    assert verify_execution_receipt(receipt)
    assert create_execution_receipt(receipt).integrity == receipt.integrity


def test_receipt_tampering_is_detected() -> None:
    receipt = create_execution_receipt(_receipt())
    changed = receipt.model_copy(update={"disposition": ExecutionDisposition.ROLLED_BACK})
    assert not verify_execution_receipt(changed)


def _committed_transaction() -> ActionTransaction:
    request = ActionRequest(
        id="request-1",
        case_id="AGE-0001",
        actor_id="agent:test",
        role=ActorRole.REASONING_RUNTIME,
        action_type="range.contain",
        target_ref="service://range/api",
        adapter="range.proxy",
        parameters={"pattern": "traversal"},
        reason="Contain the observed synthetic attack.",
        requested_at=datetime(2026, 9, 25, tzinfo=UTC),
    )
    tx = ActionTransaction(
        id="tx-1",
        case_id="AGE-0001",
        action_request=request,
        scope_digest=Digest(digest="a" * 64),
        policy_version="policy-v1",
        created_at=request.requested_at,
        updated_at=request.requested_at,
    )
    for state in (
        TransactionState.POLICY_CHECKED,
        TransactionState.AUTHORIZED,
        TransactionState.CAPABILITY_ISSUED,
        TransactionState.EXECUTING,
        TransactionState.EXECUTED,
        TransactionState.VERIFYING,
        TransactionState.VERIFIED,
        TransactionState.COMMITTED,
    ):
        tx = tx.transition_to(state, at=request.requested_at, reason="verified")
    return tx


def test_receipt_factory_requires_terminal_state_and_carries_transaction_data() -> None:
    transaction = _committed_transaction()
    receipt = receipt_from_transaction(
        transaction,
        disposition=ExecutionDisposition.COMMITTED,
        issued_at=datetime(2026, 9, 25, tzinfo=UTC),
        audit_root=Digest(digest="d" * 64),
    )
    assert receipt.transaction_id == transaction.id
    assert receipt.target_ref == transaction.action_request.target_ref
    assert verify_execution_receipt(receipt)

    executed = transaction.model_copy(update={"state": TransactionState.EXECUTED})
    with pytest.raises(ValueError, match="requires transaction state committed"):
        receipt_from_transaction(
            executed,
            disposition=ExecutionDisposition.COMMITTED,
            issued_at=datetime(2026, 9, 25, tzinfo=UTC),
            audit_root=Digest(digest="d" * 64),
        )
