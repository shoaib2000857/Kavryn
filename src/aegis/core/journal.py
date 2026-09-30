"""Optional transaction journal used to detect unresolved effects after restart.

The journal is not an authority source. A persisted incomplete mutation must
block new case actions until an operator has independently reconciled it.
"""

from __future__ import annotations

from typing import Protocol

from aegis.core.transaction import ActionTransaction


class TransactionJournalError(ValueError):
    """A snapshot is corrupt, discontinuous, or conflicts with prior history."""


class TransactionJournal(Protocol):
    def record_transaction(self, transaction: ActionTransaction) -> None:
        """Append one complete, validated revision of a transaction."""

    def transaction_for_id(self, transaction_id: str) -> ActionTransaction | None:
        """Return the last valid revision, if any."""

    def transactions_for_case(self, case_id: str) -> tuple[ActionTransaction, ...]:
        """Return the last valid revision for every case transaction."""
