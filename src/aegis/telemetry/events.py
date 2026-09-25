"""Normalized runtime telemetry events.

See docs/PRODUCT_REQUIREMENTS.md FR-DET-001 ("Normalize telemetry into
a stable event schema") and FR-DET-003 ("Distinguish observation,
inference, uncertainty, and confirmed fact"). A raw proxy log line is
untrusted (SR-INJ-001): malformed or incomplete lines raise
``TelemetryParseError`` rather than silently becoming a plausible-
looking event, and the traversal-pattern classification is explicitly
named ``inferred_classification`` — a heuristic, never treated as a
confirmed verdict.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Literal

from aegis.domain.base import AegisModel, AwareDatetime, CaseId, Digest, RecordId
from aegis.evidence.store import ArtifactStore

__all__ = [
    "EventClassification",
    "NormalizedEvent",
    "TelemetryParseError",
    "classify_path",
    "parse_proxy_log_line",
]

TELEMETRY_EVENT_SCHEMA_VERSION: Final[Literal["aegis.telemetry_event/v1"]] = (
    "aegis.telemetry_event/v1"
)

_TRAVERSAL_INDICATORS: Final[tuple[str, ...]] = ("..", "%2e%2e", "%2e.", ".%2e")
_REQUIRED_LOG_FIELDS: Final[frozenset[str]] = frozenset(
    {"ts", "method", "path", "client", "blocked", "status"}
)


class EventClassification(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"


class NormalizedEvent(AegisModel):
    schema_version: Literal["aegis.telemetry_event/v1"] = TELEMETRY_EVENT_SCHEMA_VERSION
    id: RecordId
    case_id: CaseId
    observed_at: AwareDatetime
    source: Literal["range_proxy"]
    method: str
    path: str
    status_code: int
    client_label: str
    blocked: bool
    inferred_classification: EventClassification
    raw_digest: Digest


class TelemetryParseError(ValueError):
    """Raised when a raw telemetry line cannot be safely normalized."""


def classify_path(path: str) -> EventClassification:
    """A heuristic, inference-only classification -- never a confirmed verdict."""
    lowered = path.lower()
    if any(indicator in lowered for indicator in _TRAVERSAL_INDICATORS):
        return EventClassification.SUSPICIOUS
    return EventClassification.BENIGN


def parse_proxy_log_line(
    line: str, *, case_id: str, event_id: str, artifacts: ArtifactStore
) -> NormalizedEvent:
    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        raise TelemetryParseError(f"log line is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise TelemetryParseError("log line is not a JSON object")
    missing = _REQUIRED_LOG_FIELDS - set(data)
    if missing:
        raise TelemetryParseError(f"log line is missing required field(s): {sorted(missing)}")

    raw_digest = artifacts.put(line.encode())
    path = str(data["path"])
    try:
        observed_at = datetime.fromtimestamp(float(data["ts"]), tz=UTC)
    except (TypeError, ValueError) as exc:
        raise TelemetryParseError(f"log line has an invalid timestamp: {exc}") from exc

    return NormalizedEvent(
        id=event_id,
        case_id=case_id,
        observed_at=observed_at,
        source="range_proxy",
        method=str(data["method"]),
        path=path,
        status_code=int(data["status"]),
        client_label=str(data["client"]),
        blocked=bool(data["blocked"]),
        inferred_classification=classify_path(path),
        raw_digest=raw_digest,
    )
