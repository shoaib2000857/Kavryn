from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.broker.broker import ActionBroker
from aegis.broker.registry import AdapterRegistry
from aegis.core.journal import TransactionJournalError
from aegis.core.receipt import (
    ExecutionDisposition,
    create_execution_receipt,
    receipt_from_transaction,
)
from aegis.core.transaction import ActionTransaction, TransactionState
from aegis.domain.action import ActionRequest
from aegis.domain.audit import AuditEvent, AuditEventType
from aegis.domain.base import ActorRole, Digest
from aegis.evidence.audit import AuditChainError, audit_event_digest, verify_audit_chain
from aegis.evidence.sqlite_store import ArtifactIntegrityError, SQLiteEvidenceStore


def _event(event_id: str, *, previous: Digest | None = None) -> AuditEvent:
    event = AuditEvent(
        id=event_id,
        case_id="AGE-0001",
        created_at=datetime(2026, 9, 30, tzinfo=UTC),
        event_type=AuditEventType.EVIDENCE_RECORDED,
        actor_id="control:test",
        role=ActorRole.CONTROL_PLANE,
        subject_ref="artifact://AGE-0001/sha256/" + "a" * 64,
        summary=f"evidence {event_id}",
        integrity=Digest(digest="0" * 64),
        prev_event_digest=previous,
    )
    return event.model_copy(update={"integrity": audit_event_digest(event)})


def _transaction(now: datetime) -> ActionTransaction:
    request = ActionRequest(
        id="request-journal-1",
        case_id="AGE-0001",
        actor_id="agent:test",
        role=ActorRole.REASONING_RUNTIME,
        action_type="deployment.rollout",
        target_ref="service://AGE-0001/demo",
        adapter="range.deploy",
        parameters={},
        reason="Apply an owned synthetic change.",
        requested_at=now,
    )
    return ActionTransaction(
        id="transaction-journal-1",
        case_id=request.case_id,
        action_request=request,
        scope_digest=Digest(digest="a" * 64),
        policy_version="scope-v1",
        created_at=now,
        updated_at=now,
    )


def test_artifact_and_audit_records_survive_process_reopen(tmp_path: Path) -> None:
    path = tmp_path / "evidence.sqlite3"
    with SQLiteEvidenceStore(path) as store:
        digest = store.put(b"synthetic evidence")
        first = _event("audit-first")
        store.append(first)

    with SQLiteEvidenceStore(path) as reopened:
        assert reopened.get(digest) == b"synthetic evidence"
        assert digest in reopened
        assert reopened.events_for_case("AGE-0001") == (first,)
        second = _event("audit-second", previous=first.integrity)
        reopened.append(second)
        assert verify_audit_chain(reopened.events_for_case("AGE-0001"))
        assert reopened.last_event("AGE-0001") == second


def test_read_only_store_never_creates_database_or_permits_mutations(tmp_path: Path) -> None:
    path = tmp_path / "readonly.sqlite3"
    with pytest.raises(ValueError, match="existing regular"):
        SQLiteEvidenceStore(path, read_only=True)
    assert not path.exists()
    with SQLiteEvidenceStore(path) as store:
        digest = store.put(b"existing artifact")
    before = path.read_bytes()
    with SQLiteEvidenceStore(path, read_only=True) as inspected:
        assert inspected.get(digest) == b"existing artifact"
        with pytest.raises(ValueError, match="read-only"):
            inspected.put(b"forbidden write")
        with pytest.raises(ValueError, match="read-only"):
            inspected.append(_event("forbidden-event"))
    assert path.read_bytes() == before


def test_durable_receipts_reject_replacement_tampering_and_wrong_binding(tmp_path: Path) -> None:
    path = tmp_path / "receipts.sqlite3"
    now = datetime(2026, 9, 30, tzinfo=UTC)
    tx = _transaction(now)
    with SQLiteEvidenceStore(path) as store:
        store.record_transaction(tx)
        tx = tx.transition_to(TransactionState.POLICY_CHECKED, at=now, reason="checked")
        store.record_transaction(tx)
        tx = tx.transition_to(TransactionState.DENIED, at=now, reason="denied")
        store.record_transaction(tx)
        event = _event("receipt-event")
        store.append(event)
        receipt = receipt_from_transaction(
            tx,
            disposition=ExecutionDisposition.DENIED,
            issued_at=now,
            audit_root=event.integrity,
        )
        store.put_receipt(receipt)
        wrong = create_execution_receipt(
            receipt.model_copy(update={"target_ref": "service://wrong"})
        )
        with pytest.raises(TransactionJournalError, match="does not describe"):
            store.put_receipt(wrong)
        replacement = create_execution_receipt(receipt.model_copy(update={"model_id": "different"}))
        with pytest.raises(TransactionJournalError, match="replacement"):
            store.put_receipt(replacement)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE execution_receipts SET payload = ?", (wrong.model_dump_json(),))
    with (
        SQLiteEvidenceStore(path, read_only=True) as inspected,
        pytest.raises(TransactionJournalError, match="does not describe"),
    ):
        inspected.receipt_for_transaction(tx.id)


def test_broker_can_continue_case_evidence_chain_after_restart(tmp_path: Path) -> None:
    path = tmp_path / "broker.sqlite3"
    now = datetime(2026, 9, 30, tzinfo=UTC)
    with SQLiteEvidenceStore(path) as store:
        first_broker = ActionBroker(registry=AdapterRegistry(), audit=store, artifacts=store)
        first_ref = first_broker.record_evidence_artifact(
            case_id="AGE-0001", content=b"first", now=now, producer="control:test"
        )

    with SQLiteEvidenceStore(path) as reopened:
        second_broker = ActionBroker(registry=AdapterRegistry(), audit=reopened, artifacts=reopened)
        second_ref = second_broker.record_evidence_artifact(
            case_id="AGE-0001", content=b"second", now=now, producer="control:test"
        )
        events = reopened.events_for_case("AGE-0001")
        assert len(events) == 2
        assert events[0].id != events[1].id
        assert first_ref != second_ref
        assert reopened.get(Digest(digest=first_ref.rsplit("/", 1)[-1])) == b"first"
        assert second_broker.audit_root("AGE-0001") == events[-1].integrity


def test_tampered_artifact_fails_closed_on_read(tmp_path: Path) -> None:
    path = tmp_path / "artifacts.sqlite3"
    with SQLiteEvidenceStore(path) as store:
        digest = store.put(b"trusted")

    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE artifacts SET content = ? WHERE digest = ?", (b"tampered", digest.digest)
        )

    with SQLiteEvidenceStore(path) as reopened:
        with pytest.raises(ArtifactIntegrityError):
            reopened.get(digest)
        with pytest.raises(ArtifactIntegrityError):
            assert digest in reopened


def test_tampered_audit_event_blocks_reads_and_appends(tmp_path: Path) -> None:
    path = tmp_path / "audit.sqlite3"
    first = _event("audit-first")
    with SQLiteEvidenceStore(path) as store:
        store.append(first)

    altered = first.model_dump(mode="json")
    altered["summary"] = "forged evidence"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE audit_events SET payload = ? WHERE event_id = ?",
            (json.dumps(altered), first.id),
        )

    with SQLiteEvidenceStore(path) as reopened:
        with pytest.raises(AuditChainError):
            reopened.events_for_case("AGE-0001")
        with pytest.raises(AuditChainError):
            reopened.append(_event("audit-second", previous=first.integrity))


def test_bad_event_digest_or_predecessor_is_never_persisted(tmp_path: Path) -> None:
    with SQLiteEvidenceStore(tmp_path / "audit.sqlite3") as store:
        first = _event("audit-first")
        with pytest.raises(AuditChainError):
            store.append(first.model_copy(update={"summary": "changed"}))
        store.append(first)
        with pytest.raises(AuditChainError):
            store.append(_event("audit-second"))
        with pytest.raises(AuditChainError):
            store.append(_event("audit-first", previous=first.integrity))
        assert store.events_for_case("AGE-0001") == (first,)


def test_transaction_revisions_survive_reopen_and_reject_duplicate_or_skip(tmp_path: Path) -> None:
    path = tmp_path / "journal.sqlite3"
    now = datetime(2026, 9, 30, tzinfo=UTC)
    proposed = _transaction(now)
    checked = proposed.transition_to(TransactionState.POLICY_CHECKED, at=now, reason="checked")
    authorized = checked.transition_to(TransactionState.AUTHORIZED, at=now, reason="authorized")
    with SQLiteEvidenceStore(path) as store:
        store.record_transaction(proposed)
        with pytest.raises(TransactionJournalError, match="revision"):
            store.record_transaction(authorized)
        store.record_transaction(checked)
        with pytest.raises(TransactionJournalError, match="revision"):
            store.record_transaction(checked)
    with SQLiteEvidenceStore(path) as reopened:
        assert reopened.transaction_for_id(proposed.id) == checked
        assert reopened.transactions_for_case(proposed.case_id) == (checked,)
        reopened.record_transaction(authorized)
        assert reopened.transaction_for_id(proposed.id) == authorized


def test_tampered_transaction_revision_blocks_reads_and_appends(tmp_path: Path) -> None:
    path = tmp_path / "journal.sqlite3"
    now = datetime(2026, 9, 30, tzinfo=UTC)
    proposed = _transaction(now)
    checked = proposed.transition_to(TransactionState.POLICY_CHECKED, at=now, reason="checked")
    with SQLiteEvidenceStore(path) as store:
        store.record_transaction(proposed)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE transaction_snapshots SET payload = ? WHERE transaction_id = ?",
            ("{}", proposed.id),
        )
    with SQLiteEvidenceStore(path) as reopened:
        with pytest.raises(TransactionJournalError, match="digest mismatch"):
            reopened.transaction_for_id(proposed.id)
        with pytest.raises(TransactionJournalError, match="digest mismatch"):
            reopened.record_transaction(checked)


def test_version_one_evidence_database_upgrades_without_losing_artifacts(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    content = b"legacy synthetic artifact"
    digest = Digest(digest=hashlib.sha256(content).hexdigest())
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE artifacts (digest TEXT PRIMARY KEY, content BLOB NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE audit_events (case_id TEXT NOT NULL, ordinal INTEGER NOT NULL, "
            "event_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, PRIMARY KEY(case_id, ordinal))"
        )
        connection.execute(
            "INSERT INTO artifacts (digest, content) VALUES (?, ?)", (digest.digest, content)
        )
        connection.execute("PRAGMA user_version=1")
    with SQLiteEvidenceStore(path) as upgraded:
        assert upgraded.get(digest) == content
        upgraded.record_transaction(_transaction(datetime(2026, 9, 30, tzinfo=UTC)))
        assert upgraded.transaction_for_id("transaction-journal-1") is not None
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
