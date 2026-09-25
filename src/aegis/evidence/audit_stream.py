"""Stable JSONL export and verification for per-case audit chains.

The stream format makes existing in-memory audit evidence portable. It does
not make a local file immutable or authenticate its writer; verification only
detects edits relative to the stored per-event digests and chain links.
"""

from __future__ import annotations

import json

from aegis.domain.audit import AuditEvent
from aegis.evidence.audit import verify_audit_chain

__all__ = ["AuditStreamError", "export_audit_jsonl", "parse_audit_jsonl"]


class AuditStreamError(ValueError):
    """Raised when an exported stream is malformed, mixed-case, or tampered."""


def export_audit_jsonl(events: tuple[AuditEvent, ...]) -> str:
    """Serialize one verified case chain in deterministic compact JSONL."""
    if not events:
        raise AuditStreamError("cannot export an empty audit chain")
    case_ids = {event.case_id for event in events}
    if len(case_ids) != 1:
        raise AuditStreamError("audit JSONL export must contain exactly one case chain")
    if not verify_audit_chain(events):
        raise AuditStreamError("refusing to export an invalid audit chain")
    return "".join(
        json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) + "\n"
        for event in events
    )


def parse_audit_jsonl(content: str) -> tuple[AuditEvent, ...]:
    """Parse and verify a per-case JSONL stream; fail closed on any bad line."""
    events: list[AuditEvent] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            raise AuditStreamError(f"blank line at {line_number}")
        try:
            event = AuditEvent.model_validate_json(line)
        except ValueError as exc:
            raise AuditStreamError(f"invalid audit event on line {line_number}") from exc
        events.append(event)
    if not events:
        raise AuditStreamError("audit stream is empty")
    if len({event.case_id for event in events}) != 1:
        raise AuditStreamError("audit stream must contain exactly one case chain")
    verified = tuple(events)
    if not verify_audit_chain(verified):
        raise AuditStreamError("audit stream content or chain verification failed")
    return verified
