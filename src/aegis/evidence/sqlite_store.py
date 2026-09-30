"""Durable local artifact and audit storage for trusted control-plane processes.

This implements the existing ``ArtifactStore`` and ``AuditSink`` protocols. SQLite
persists each write before returning, but this is not an authenticated or immutable
audit service: anyone who can replace the database can replace its contents.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import RLock
from typing import Self

from aegis.core.journal import TransactionJournalError
from aegis.core.receipt import ExecutionReceipt, receipt_from_transaction, verify_execution_receipt
from aegis.core.transaction import ActionTransaction, TransactionState
from aegis.domain.audit import AuditEvent
from aegis.domain.base import Digest
from aegis.evidence.audit import AuditChainError, audit_event_digest, verify_audit_chain
from aegis.evidence.store import ArtifactNotFoundError, sha256_digest

__all__ = ["ArtifactIntegrityError", "SQLiteEvidenceStore"]


class ArtifactIntegrityError(ValueError):
    """Stored bytes do not match their content address."""


class SQLiteEvidenceStore:
    """A local durable implementation of both evidence-store protocols.

    Construct one instance with a trusted operator-selected database path and pass
    it as both ``audit`` and ``artifacts`` to ``ActionBroker``. Each method is safe
    for threads sharing an instance; SQLite serializes writes across processes.
    Transaction snapshots are also append-only persisted here when the store is
    passed as the broker's optional journal. Capabilities and approvals are not
    persisted, and the journal alone cannot safely resume an unfinished action.
    """

    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        database_path = Path(path)
        self._read_only = read_only
        self._lock = RLock()
        if read_only:
            if database_path.is_symlink() or not database_path.is_file():
                raise ValueError("read-only inspection requires an existing regular database")
            self._connection = sqlite3.connect(
                database_path.resolve().as_uri() + "?mode=ro",
                uri=True,
                timeout=10.0,
                isolation_level=None,
                check_same_thread=False,
            )
            self._connection.execute("PRAGMA query_only=ON")
            version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (2, 3):
                self._connection.close()
                raise ValueError("read-only inspection requires schema version 2 or 3")
            return
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            database_path, timeout=10.0, isolation_level=None, check_same_thread=False
        )
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in (0, 1, 2, 3):
            self._connection.close()
            raise ValueError(f"unsupported evidence database schema version: {version}")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                digest TEXT PRIMARY KEY,
                content BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                case_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                PRIMARY KEY (case_id, ordinal)
            );
            CREATE TABLE IF NOT EXISTS transaction_snapshots (
                transaction_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                payload TEXT NOT NULL,
                digest TEXT NOT NULL,
                PRIMARY KEY (transaction_id, revision)
            );
            CREATE INDEX IF NOT EXISTS idx_transaction_snapshots_case
                ON transaction_snapshots (case_id, transaction_id);
            CREATE TABLE IF NOT EXISTS execution_receipts (
                transaction_id TEXT PRIMARY KEY,
                receipt_id TEXT NOT NULL UNIQUE,
                case_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """
        )
        self._connection.execute("PRAGMA user_version=3")

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()

    def put(self, content: bytes) -> Digest:
        self._require_writable()
        digest = sha256_digest(content)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "INSERT OR IGNORE INTO artifacts (digest, content) VALUES (?, ?)",
                    (digest.digest, content),
                )
                row = self._connection.execute(
                    "SELECT content FROM artifacts WHERE digest = ?", (digest.digest,)
                ).fetchone()
                if row is None or bytes(row[0]) != content:
                    raise ArtifactIntegrityError("stored artifact differs from its content address")
                self._connection.commit()
            except BaseException:
                self._connection.rollback()
                raise
        return digest

    def get(self, digest: Digest) -> bytes:
        with self._lock:
            row = self._connection.execute(
                "SELECT content FROM artifacts WHERE digest = ?", (digest.digest,)
            ).fetchone()
        if row is None:
            raise ArtifactNotFoundError(digest.digest)
        content = bytes(row[0])
        if sha256_digest(content) != digest:
            raise ArtifactIntegrityError("stored artifact failed digest verification")
        return content

    def __contains__(self, digest: Digest) -> bool:
        try:
            self.get(digest)
        except ArtifactNotFoundError:
            return False
        return True

    def _events_for_case_unlocked(self, case_id: str) -> tuple[AuditEvent, ...]:
        rows = self._connection.execute(
            "SELECT ordinal, event_id, payload FROM audit_events "
            "WHERE case_id = ? ORDER BY ordinal",
            (case_id,),
        ).fetchall()
        events: list[AuditEvent] = []
        for expected_ordinal, (ordinal, event_id, payload) in enumerate(rows, start=1):
            if ordinal != expected_ordinal:
                raise AuditChainError("audit event sequence contains a gap")
            try:
                event = AuditEvent.model_validate_json(payload)
            except ValueError as exc:
                raise AuditChainError("stored audit event is malformed") from exc
            if event.case_id != case_id:
                raise AuditChainError("stored audit event has a different case identifier")
            if event.id != event_id:
                raise AuditChainError("stored audit event index differs from its content")
            events.append(event)
        result = tuple(events)
        if not verify_audit_chain(result):
            raise AuditChainError("stored audit event content or chain failed verification")
        return result

    def events_for_case(self, case_id: str) -> tuple[AuditEvent, ...]:
        with self._lock:
            return self._events_for_case_unlocked(case_id)

    def last_event(self, case_id: str) -> AuditEvent | None:
        events = self.events_for_case(case_id)
        return events[-1] if events else None

    def append(self, event: AuditEvent) -> None:
        self._require_writable()
        if audit_event_digest(event) != event.integrity:
            raise AuditChainError("audit event content does not match its integrity digest")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                history = self._events_for_case_unlocked(event.case_id)
                expected_prev = history[-1].integrity if history else None
                if event.prev_event_digest != expected_prev:
                    raise AuditChainError("audit event does not chain onto the prior event")
                self._connection.execute(
                    "INSERT INTO audit_events (case_id, ordinal, event_id, payload) "
                    "VALUES (?, ?, ?, ?)",
                    (event.case_id, len(history) + 1, event.id, event.model_dump_json()),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                self._connection.rollback()
                raise AuditChainError("duplicate or conflicting audit event") from exc
            except BaseException:
                self._connection.rollback()
                raise

    def _transaction_history_unlocked(self, transaction_id: str) -> tuple[ActionTransaction, ...]:
        rows = self._connection.execute(
            "SELECT case_id, revision, payload, digest FROM transaction_snapshots "
            "WHERE transaction_id = ? ORDER BY revision",
            (transaction_id,),
        ).fetchall()
        history: list[ActionTransaction] = []
        for expected_revision, (case_id, revision, payload, digest) in enumerate(rows):
            if revision != expected_revision:
                raise TransactionJournalError("transaction revision sequence has a gap")
            if sha256_digest(payload.encode()).digest != digest:
                raise TransactionJournalError("transaction snapshot digest mismatch")
            try:
                snapshot = ActionTransaction.model_validate_json(payload)
            except ValueError as exc:
                raise TransactionJournalError("stored transaction snapshot is malformed") from exc
            if snapshot.id != transaction_id or snapshot.case_id != case_id:
                raise TransactionJournalError("transaction snapshot index differs from content")
            if len(snapshot.transitions) != revision:
                raise TransactionJournalError("transaction revision does not match transitions")
            if history:
                self._validate_transaction_step(history[-1], snapshot)
            elif snapshot.state is not TransactionState.PROPOSED:
                raise TransactionJournalError("first transaction snapshot is not proposed")
            history.append(snapshot)
        return tuple(history)

    @staticmethod
    def _validate_transaction_step(previous: ActionTransaction, current: ActionTransaction) -> None:
        if (
            current.id != previous.id
            or current.case_id != previous.case_id
            or current.action_request != previous.action_request
            or current.action_definition_digest != previous.action_definition_digest
            or current.scope_digest != previous.scope_digest
            or current.policy_version != previous.policy_version
            or current.created_at != previous.created_at
            or len(current.transitions) != len(previous.transitions) + 1
            or current.transitions[:-1] != previous.transitions
        ):
            raise TransactionJournalError("transaction revision changes immutable identity")
        last = current.transitions[-1]
        try:
            expected = previous.transition_to(last.to_state, at=last.at, reason=last.reason)
        except ValueError as exc:
            raise TransactionJournalError("transaction revision has an illegal transition") from exc
        if current.state is not expected.state or current.transitions != expected.transitions:
            raise TransactionJournalError("transaction revision has a discontinuous transition")

    def record_transaction(self, transaction: ActionTransaction) -> None:
        self._require_writable()
        payload = transaction.model_dump_json()
        digest = sha256_digest(payload.encode()).digest
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                history = self._transaction_history_unlocked(transaction.id)
                if history:
                    self._validate_transaction_step(history[-1], transaction)
                elif transaction.state is not TransactionState.PROPOSED or transaction.transitions:
                    raise TransactionJournalError("first transaction snapshot must be proposed")
                if len(transaction.transitions) != len(history):
                    raise TransactionJournalError("transaction revision is stale or skipped")
                self._connection.execute(
                    "INSERT INTO transaction_snapshots "
                    "(transaction_id, case_id, revision, payload, digest) VALUES (?, ?, ?, ?, ?)",
                    (transaction.id, transaction.case_id, len(history), payload, digest),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                self._connection.rollback()
                raise TransactionJournalError(
                    "duplicate or conflicting transaction revision"
                ) from exc
            except BaseException:
                self._connection.rollback()
                raise

    def transaction_for_id(self, transaction_id: str) -> ActionTransaction | None:
        with self._lock:
            history = self._transaction_history_unlocked(transaction_id)
        return history[-1] if history else None

    def transactions_for_case(self, case_id: str) -> tuple[ActionTransaction, ...]:
        with self._lock:
            ids = self._connection.execute(
                "SELECT DISTINCT transaction_id FROM transaction_snapshots "
                "WHERE case_id = ? ORDER BY transaction_id",
                (case_id,),
            ).fetchall()
            result: list[ActionTransaction] = []
            for (transaction_id,) in ids:
                history = self._transaction_history_unlocked(transaction_id)
                if not history or history[-1].case_id != case_id:
                    raise TransactionJournalError("transaction case index differs from content")
                result.append(history[-1])
        return tuple(result)

    def _require_writable(self) -> None:
        if self._read_only:
            raise ValueError("evidence store was opened read-only")

    def _validate_receipt_unlocked(self, receipt: ExecutionReceipt) -> None:
        if not verify_execution_receipt(receipt):
            raise ArtifactIntegrityError("receipt content failed digest verification")
        history = self._transaction_history_unlocked(receipt.transaction_id)
        if not history:
            raise TransactionJournalError("receipt requires a journaled terminal transaction")
        events = self._events_for_case_unlocked(receipt.case_id)
        if (
            receipt.audit_root is None
            or not events
            or receipt.audit_root not in {event.integrity for event in events}
        ):
            raise AuditChainError("receipt audit root is absent from its verified case chain")
        expected = receipt_from_transaction(
            history[-1],
            disposition=receipt.disposition,
            issued_at=receipt.issued_at,
            audit_root=receipt.audit_root,
            model_provider=receipt.model_provider,
            model_id=receipt.model_id,
        )
        if expected != receipt:
            raise TransactionJournalError("receipt does not describe its journaled transaction")

    def put_receipt(self, receipt: ExecutionReceipt) -> None:
        """Append once, matching terminal journal and current verified audit head.

        Identical replay is idempotent; replacement is forbidden. These checks
        bind local records, not authenticated producers or external target state.
        """
        self._require_writable()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._validate_receipt_unlocked(receipt)
                existing = self._connection.execute(
                    "SELECT payload FROM execution_receipts WHERE transaction_id = ?",
                    (receipt.transaction_id,),
                ).fetchone()
                if existing is not None:
                    if existing[0] != receipt.model_dump_json():
                        raise TransactionJournalError("receipt replacement is forbidden")
                else:
                    if (
                        self._events_for_case_unlocked(receipt.case_id)[-1].integrity
                        != receipt.audit_root
                    ):
                        raise AuditChainError("new receipt must bind the current audit head")
                    self._connection.execute(
                        "INSERT INTO execution_receipts VALUES (?, ?, ?, ?)",
                        (
                            receipt.transaction_id,
                            receipt.id,
                            receipt.case_id,
                            receipt.model_dump_json(),
                        ),
                    )
                self._connection.commit()
            except BaseException:
                self._connection.rollback()
                raise

    def receipt_for_transaction(self, transaction_id: str) -> ExecutionReceipt | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT receipt_id, case_id, payload FROM execution_receipts "
                "WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()
            if row is None:
                return None
            try:
                receipt = ExecutionReceipt.model_validate_json(row[2])
            except ValueError as exc:
                raise ArtifactIntegrityError("stored receipt is malformed") from exc
            if (receipt.transaction_id, receipt.id, receipt.case_id) != (
                transaction_id,
                row[0],
                row[1],
            ):
                raise ArtifactIntegrityError("receipt index differs from its content")
            self._validate_receipt_unlocked(receipt)
            return receipt
