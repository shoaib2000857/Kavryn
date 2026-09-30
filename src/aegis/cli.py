"""Local operational diagnostics and read-only integrity inspection."""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
from pathlib import Path

from aegis.core.receipt import ExecutionReceipt, verify_execution_receipt
from aegis.core.transaction import TransactionState
from aegis.evidence.audit_stream import parse_audit_jsonl
from aegis.evidence.sqlite_store import SQLiteEvidenceStore

MAX_INPUT_BYTES = 8 * 1024 * 1024


def _read(path: Path) -> str:
    with path.open("rb") as stream:
        data = stream.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds 8 MiB inspection limit")
    return data.decode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kavryn", description=__doc__)
    parser.add_argument("--version", action="version", version="Kavryn 0.1.0")
    kinds = parser.add_subparsers(dest="kind", required=True)
    kinds.add_parser("doctor", help="inspect local prerequisites without invoking services/models")
    demo = kinds.add_parser("demo", help="model-free in-memory SDK simulation; not a benchmark")
    demo.add_argument("--fail-verification", action="store_true")
    journal = kinds.add_parser("journal").add_subparsers(dest="command", required=True)
    inspect = journal.add_parser("inspect", help="inspect without clearing quarantine or replaying")
    inspect.add_argument("path", type=Path)
    inspect.add_argument("--case", required=True)
    for kind in ("audit", "receipt"):
        commands = kinds.add_parser(kind).add_subparsers(dest="command", required=True)
        verify = commands.add_parser("verify", help="check integrity, not authenticity or safety")
        verify.add_argument("path", type=Path)
        verify.add_argument(
            "--expected-head", help="independently obtained audit SHA-256 hex digest"
        )
        if kind == "receipt":
            verify.add_argument(
                "--audit", type=Path, help="also verify receipt-to-case/audit-head link"
            )
    args = parser.parse_args(argv)
    root: str | None
    try:
        if args.kind == "demo":
            from aegis.demo import run_transaction_demo

            receipt = run_transaction_demo(fail_verification=args.fail_verification)
            print(
                json.dumps(
                    {
                        "simulation_only": True,
                        "model_contacted": False,
                        "receipt": receipt.model_dump(mode="json"),
                    }
                )
            )
            return 0
        if args.kind == "doctor":
            paths = (Path("/"), Path.cwd())
            print(
                json.dumps(
                    {
                        "python": sys.version.split()[0],
                        "executables_present": {
                            tool: shutil.which(tool) is not None
                            for tool in ("patch", "docker", "runsc")
                        },
                        "storage": [
                            {"path": str(path), "free_bytes": shutil.disk_usage(path).free}
                            for path in paths
                        ],
                        "model_contacted": False,
                        "sandbox_tested": False,
                        "warning": "Presence is not readiness or an isolation guarantee.",
                    }
                )
            )
            return 0
        if args.kind == "journal":
            with SQLiteEvidenceStore(args.path, read_only=True) as store:
                transactions = store.transactions_for_case(args.case)
                events = store.events_for_case(args.case)
                print(
                    json.dumps(
                        {
                            "case_id": args.case,
                            "audit_records_checked": len(events),
                            "transactions": [
                                {
                                    "transaction_id": tx.id,
                                    "state": tx.state.value,
                                    "action_type": tx.action_request.action_type,
                                    "review_required": any(
                                        step.to_state is TransactionState.EXECUTING
                                        for step in tx.transitions
                                    )
                                    and tx.state
                                    not in (
                                        TransactionState.COMMITTED,
                                        TransactionState.ROLLED_BACK,
                                    ),
                                }
                                for tx in transactions
                            ],
                            "inspection_only": True,
                            "capabilities_restored": False,
                            "warning": "Conservative review flags; no target reconciliation, "
                            "quarantine clearance, or action replay.",
                        }
                    )
                )
            return 0
        if args.kind == "audit":
            events = parse_audit_jsonl(_read(args.path))
            case_id, root = events[0].case_id, events[-1].integrity.digest
            count = len(events)
        else:
            receipt = ExecutionReceipt.model_validate_json(_read(args.path))
            if not verify_execution_receipt(receipt):
                raise ValueError("receipt integrity mismatch")
            case_id = receipt.case_id
            root = receipt.audit_root.digest if receipt.audit_root else None
            count = 1
            if args.audit:
                events = parse_audit_jsonl(_read(args.audit))
                if events[0].case_id != case_id or events[-1].integrity.digest != root:
                    raise ValueError("receipt and audit stream are not linked")
        if args.expected_head is not None and root != args.expected_head:
            raise ValueError("audit root differs from independently supplied expected head")
        print(
            json.dumps(
                {
                    "integrity_valid": True,
                    "case_id": case_id,
                    "audit_head": root,
                    "records_checked": count,
                    "audit_chain_checked": args.kind == "audit" or args.audit is not None,
                    "authenticated_origin": False,
                    "safety_verified": False,
                    "warning": "Hashes/linkage alone do not authenticate authority "
                    "or prove action safety.",
                }
            )
        )
        return 0
    except (OSError, ValueError, sqlite3.Error) as exc:
        # Validation errors may embed input data. Do not echo receipt contents.
        print(f"integrity inspection failed ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
