from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.cli import main
from aegis.core.receipt import (
    ExecutionDisposition,
    ExecutionReceipt,
    create_execution_receipt,
    verify_execution_receipt,
)
from aegis.domain.audit import AuditEvent, AuditEventType
from aegis.domain.base import ActorRole, Digest
from aegis.evidence.audit import audit_event_digest
from aegis.evidence.audit_stream import export_audit_jsonl
from aegis.evidence.sqlite_store import SQLiteEvidenceStore


@pytest.mark.parametrize("fail, disposition", [(False, "committed"), (True, "rolled_back")])
def test_model_free_demo(fail: bool, disposition: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["demo"] + (["--fail-verification"] if fail else [])) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["simulation_only"] and not data["model_contacted"]
    receipt = ExecutionReceipt.model_validate(data["receipt"])
    assert verify_execution_receipt(receipt) and receipt.disposition.value == disposition


def test_doctor_does_not_contact_model_or_claim_sandbox_readiness(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["doctor"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert not result["model_contacted"] and not result["sandbox_tested"]
    assert all(item["free_bytes"] >= 0 for item in result["storage"])


def test_journal_inspection_is_read_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "journal.sqlite3"
    assert main(["journal", "inspect", str(path), "--case", "AGE-0001"]) == 2
    assert not path.exists()
    with SQLiteEvidenceStore(path):
        pass
    before = path.read_bytes()
    assert main(["journal", "inspect", str(path), "--case", "AGE-0001"]) == 0
    assert json.loads(capsys.readouterr().out)["inspection_only"]
    assert path.read_bytes() == before


def fixture_files(tmp_path: Path) -> tuple[Path, Path, str]:
    event = AuditEvent(
        id="event-1",
        case_id="AGE-0001",
        created_at=datetime(2026, 9, 30, tzinfo=UTC),
        event_type=AuditEventType.POLICY_DECISION_RECORDED,
        actor_id="control:test",
        role=ActorRole.CONTROL_PLANE,
        subject_ref="transaction://tx-1",
        summary="decision",
        integrity=Digest(digest="0" * 64),
    )
    event = event.model_copy(update={"integrity": audit_event_digest(event)})
    audit = tmp_path / "audit.jsonl"
    audit.write_text(export_audit_jsonl((event,)))
    receipt = create_execution_receipt(
        ExecutionReceipt(
            id="receipt-1",
            transaction_id="tx-1",
            case_id="AGE-0001",
            actor_id="control:test",
            action_type="range.contain",
            adapter="range.proxy",
            target_ref="service://range",
            scope_digest=Digest(digest="a" * 64),
            policy_version="v1",
            disposition=ExecutionDisposition.DENIED,
            audit_root=event.integrity,
            issued_at=event.created_at,
            integrity=Digest(digest="0" * 64),
        )
    )
    path = tmp_path / "receipt.json"
    path.write_text(receipt.model_dump_json())
    return path, audit, event.integrity.digest


def test_cli_receipt_audit_link_and_external_head(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    receipt, audit, head = fixture_files(tmp_path)
    assert (
        main(["receipt", "verify", str(receipt), "--audit", str(audit), "--expected-head", head])
        == 0
    )
    data = json.loads(capsys.readouterr().out)
    assert (
        data["integrity_valid"] and not data["authenticated_origin"] and not data["safety_verified"]
    )
    assert main(["audit", "verify", str(audit), "--expected-head", head]) == 0


def test_cli_wrong_anchor_and_tampered_receipt_fail_closed(tmp_path: Path) -> None:
    receipt, audit, _ = fixture_files(tmp_path)
    assert main(["audit", "verify", str(audit), "--expected-head", "0" * 64]) == 2
    data = json.loads(receipt.read_text())
    data["policy_version"] = "tampered"
    receipt.write_text(json.dumps(data))
    assert main(["receipt", "verify", str(receipt)]) == 2


@pytest.mark.parametrize("mismatch", ["case", "root"])
def test_cli_rejects_validly_rehashed_but_unlinked_receipt(tmp_path: Path, mismatch: str) -> None:
    path, audit, _ = fixture_files(tmp_path)
    receipt = ExecutionReceipt.model_validate_json(path.read_text())
    updates: dict[str, object] = (
        {"case_id": "AGE-0002"} if mismatch == "case" else {"audit_root": Digest(digest="f" * 64)}
    )
    changed = create_execution_receipt(receipt.model_copy(update=updates))
    path.write_text(changed.model_dump_json())
    assert main(["receipt", "verify", str(path), "--audit", str(audit)]) == 2


def test_cli_missing_or_private_invalid_input_is_not_echoed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "bad.json"
    assert main(["receipt", "verify", str(path)]) == 2
    path.write_text('{"secret": "private-marker"}')
    assert main(["receipt", "verify", str(path)]) == 2
    assert "private-marker" not in capsys.readouterr().err
