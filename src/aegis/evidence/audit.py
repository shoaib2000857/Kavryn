"""An append-only, hash-chain-verifying audit sink.

See docs/PRODUCT_REQUIREMENTS.md SR-AUD-001/SR-AUD-002 and
docs/THREAT_MODEL.md T07. This in-memory implementation is the Change 2
deliverable; an out-of-band external sink is deferred, but must satisfy
the same ``AuditSink`` protocol. There is no update or delete method:
append-only is enforced by the interface shape itself, not just by
convention.
"""

from __future__ import annotations

import json
from typing import Protocol

from aegis.domain.audit import AuditEvent
from aegis.domain.base import Digest
from aegis.evidence.store import sha256_digest

__all__ = [
    "AuditChainError",
    "AuditSink",
    "InMemoryAuditSink",
    "audit_event_digest",
    "verify_audit_chain",
]


class AuditChainError(ValueError):
    """Raised when an appended event does not correctly chain onto the prior one."""


class AuditSink(Protocol):
    def append(self, event: AuditEvent) -> None:
        """Append ``event``, validating its hash-chain linkage first."""

    def events_for_case(self, case_id: str) -> tuple[AuditEvent, ...]:
        """Return every event recorded for ``case_id``, in append order."""

    def last_event(self, case_id: str) -> AuditEvent | None:
        """Return the most recently appended event for ``case_id``, if any."""


def audit_event_digest(event: AuditEvent) -> Digest:
    """Recompute an event's content digest using stable field serialization."""
    payload = json.dumps(
        {
            "id": event.id,
            "case_id": event.case_id,
            "created_at": event.created_at.isoformat(),
            "event_type": event.event_type.value,
            "actor_id": event.actor_id,
            "role": event.role.value,
            "subject_ref": event.subject_ref,
            "summary": event.summary,
        },
        sort_keys=True,
    ).encode()
    return sha256_digest(payload)


def verify_audit_chain(events: tuple[AuditEvent, ...]) -> bool:
    """Verify event content and predecessor links in append order.

    This detects changes relative to existing hashes; it does not authenticate
    who created the stream or prevent an attacker from rewriting and
    re-hashing the entire stream. Durable external anchoring remains future work.
    """
    previous: Digest | None = None
    for event in events:
        if event.prev_event_digest != previous or audit_event_digest(event) != event.integrity:
            return False
        previous = event.integrity
    return True


class InMemoryAuditSink:
    """A process-local audit sink with hash-chain integrity checking.

    The first event appended for a case must have ``prev_event_digest
    is None``; every subsequent event must set ``prev_event_digest`` to
    the ``integrity`` digest of the immediately preceding event for that
    case. A violation — a forged, reordered, or spliced event — raises
    ``AuditChainError`` and is not appended.
    """

    def __init__(self) -> None:
        self._events: dict[str, list[AuditEvent]] = {}

    def append(self, event: AuditEvent) -> None:
        history = self._events.setdefault(event.case_id, [])
        expected_prev = history[-1].integrity if history else None
        if event.prev_event_digest != expected_prev:
            raise AuditChainError(
                f"event '{event.id}' does not chain onto the prior event for case "
                f"'{event.case_id}' (expected prev_event_digest={expected_prev!r}, "
                f"got {event.prev_event_digest!r})"
            )
        history.append(event)

    def events_for_case(self, case_id: str) -> tuple[AuditEvent, ...]:
        return tuple(self._events.get(case_id, ()))

    def last_event(self, case_id: str) -> AuditEvent | None:
        history = self._events.get(case_id)
        return history[-1] if history else None
