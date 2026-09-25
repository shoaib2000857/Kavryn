from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aegis.core.transaction import (
    ActionTransaction,
    IllegalTransactionTransitionError,
    TransactionState,
)
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole, Digest

NOW = datetime(2026, 9, 25, tzinfo=UTC)


def _request() -> ActionRequest:
    return ActionRequest(
        id="request-1",
        case_id="AGE-0001",
        actor_id="agent:test",
        role=ActorRole.REASONING_RUNTIME,
        action_type="range.contain",
        target_ref="service://range/api",
        adapter="range.proxy",
        parameters={"pattern": "traversal"},
        reason="Contain the observed synthetic attack.",
        requested_at=NOW,
    )


def _transaction() -> ActionTransaction:
    return ActionTransaction(
        id="tx-1",
        case_id="AGE-0001",
        action_request=_request(),
        scope_digest=Digest(digest="a" * 64),
        policy_version="policy-v1",
        created_at=NOW,
        updated_at=NOW,
        reversible=True,
    )


def test_transaction_records_valid_propose_authorize_execute_verify_commit_path() -> None:
    tx = _transaction()
    for state in (
        TransactionState.POLICY_CHECKED,
        TransactionState.AUTHORIZED,
        TransactionState.CAPABILITY_ISSUED,
        TransactionState.STAGED,
        TransactionState.EXECUTING,
        TransactionState.EXECUTED,
        TransactionState.VERIFYING,
        TransactionState.VERIFIED,
        TransactionState.COMMITTED,
    ):
        tx = tx.transition_to(
            state, at=NOW + timedelta(seconds=len(tx.transitions) + 1), reason="test"
        )

    assert tx.state is TransactionState.COMMITTED
    assert len(tx.transitions) == 9
    assert tx.transitions[0].from_state is TransactionState.PROPOSED
    assert tx.transitions[-1].to_state is TransactionState.COMMITTED


def test_approval_and_verified_transaction_can_roll_back() -> None:
    tx = _transaction()
    for state in (
        TransactionState.POLICY_CHECKED,
        TransactionState.AWAITING_APPROVAL,
        TransactionState.AUTHORIZED,
        TransactionState.CAPABILITY_ISSUED,
        TransactionState.EXECUTING,
        TransactionState.EXECUTED,
        TransactionState.VERIFYING,
        TransactionState.VERIFIED,
        TransactionState.ROLLING_BACK,
        TransactionState.ROLLED_BACK,
    ):
        tx = tx.transition_to(
            state, at=NOW + timedelta(seconds=len(tx.transitions) + 1), reason="test"
        )
    assert tx.state is TransactionState.ROLLED_BACK


def test_illegal_transition_and_terminal_state_mutation_are_rejected() -> None:
    tx = _transaction()
    with pytest.raises(IllegalTransactionTransitionError, match="proposed -> committed"):
        tx.transition_to(TransactionState.COMMITTED, at=NOW, reason="skip checks")

    denied = tx.transition_to(TransactionState.POLICY_CHECKED, at=NOW, reason="policy evaluated")
    denied = denied.transition_to(TransactionState.DENIED, at=NOW, reason="outside scope")
    with pytest.raises(IllegalTransactionTransitionError, match="denied -> authorized"):
        denied.transition_to(TransactionState.AUTHORIZED, at=NOW, reason="should be impossible")


def test_transaction_requires_matching_case_and_contiguous_history() -> None:
    with pytest.raises(ValueError, match="case_id must match"):
        ActionTransaction(
            id="tx-bad",
            case_id="AGE-0002",
            action_request=_request(),
            scope_digest=Digest(digest="a" * 64),
            policy_version="policy-v1",
            created_at=NOW,
            updated_at=NOW,
        )
