"""Normalized static-analysis findings.

See docs/PRODUCT_REQUIREMENTS.md FR-VUL-002 ("Deduplicate and correlate
findings without treating scanner output as ground truth") and
docs/EVIDENCE_AND_ASSURANCE.md ("preserve raw input separately from
parsed/normalized records"). Tool output is untrusted
(docs/THREAT_MODEL.md SR-INJ-001): a malformed or unexpectedly-shaped
result never silently becomes "zero findings" — that would be a
dangerous false negative — it raises ``FindingsParseError`` instead, so
the adapter can mark the run as failed rather than falsely clean
(docs/WORKFLOWS.md failure semantics: "Parser failure: preserve raw
artifact, mark untrusted, do not infer success").
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import Field

from aegis.domain.base import AegisModel

__all__ = ["FindingsParseError", "NormalizedFinding", "parse_bandit_json", "parse_semgrep_json"]


class FindingsParseError(ValueError):
    """Raised when scanner output cannot be normalized safely."""


class NormalizedFinding(AegisModel):
    tool: Literal["semgrep", "bandit"]
    rule_id: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line: int = Field(ge=0)
    severity: str
    message: str


def _require_results_list(data: Any, *, tool: str) -> list[Any]:
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise FindingsParseError(f"{tool} output is missing a 'results' list")
    return results


def parse_semgrep_json(raw: str) -> tuple[NormalizedFinding, ...]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FindingsParseError(f"semgrep output is not valid JSON: {exc}") from exc
    results = _require_results_list(data, tool="semgrep")
    findings = []
    for entry in results:
        try:
            extra = entry.get("extra", {})
            findings.append(
                NormalizedFinding(
                    tool="semgrep",
                    rule_id=str(entry["check_id"]),
                    file=str(entry["path"]),
                    line=int(entry["start"]["line"]),
                    severity=str(extra.get("severity", "unknown")),
                    message=str(extra.get("message", "")),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise FindingsParseError(f"malformed semgrep result entry: {exc}") from exc
    return tuple(findings)


def parse_bandit_json(raw: str) -> tuple[NormalizedFinding, ...]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FindingsParseError(f"bandit output is not valid JSON: {exc}") from exc
    results = _require_results_list(data, tool="bandit")
    findings = []
    for entry in results:
        try:
            findings.append(
                NormalizedFinding(
                    tool="bandit",
                    rule_id=str(entry["test_id"]),
                    file=str(entry["filename"]),
                    line=int(entry["line_number"]),
                    severity=str(entry.get("issue_severity", "UNKNOWN")),
                    message=str(entry.get("issue_text", "")),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise FindingsParseError(f"malformed bandit result entry: {exc}") from exc
    return tuple(findings)
