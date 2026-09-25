"""Verify a per-case Aegis audit JSONL stream without rewriting it."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from aegis.evidence.audit_stream import AuditStreamError, parse_audit_jsonl  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stream", type=Path, help="path to one case's exported audit JSONL")
    args = parser.parse_args()
    try:
        events = parse_audit_jsonl(args.stream.read_text(encoding="utf-8"))
    except (OSError, AuditStreamError) as exc:
        parser.exit(2, f"audit verification failed: {exc}\n")
    head = events[-1].integrity.digest
    print(f"verified {len(events)} events for {events[0].case_id}; chain head sha256:{head}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
