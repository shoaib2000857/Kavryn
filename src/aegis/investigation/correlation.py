"""Deterministically correlate range telemetry with source findings.

The result is explicitly a hypothesis. Correlation requires same-case
records, a configured route-to-source binding, a suspicious normalized
event, and equality between scan-source and deployment-source digests.
It does not establish that a finding caused an event.
"""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
from typing import Final, Literal

from pydantic import Field, model_validator

from aegis.domain.base import AegisModel, CaseId, Digest, RecordId, Uri
from aegis.range.provenance import DeploymentProvenance
from aegis.telemetry.events import EventClassification, NormalizedEvent
from aegis.tools.findings import NormalizedFinding

__all__ = [
    "CorrelationReport",
    "InvestigationHypothesis",
    "RouteSourceBinding",
    "correlate_evidence",
]

_HYPOTHESIS_SCHEMA: Final[Literal["aegis.investigation_hypothesis/v1"]] = (
    "aegis.investigation_hypothesis/v1"
)
_REPORT_SCHEMA: Final[Literal["aegis.correlation_report/v1"]] = "aegis.correlation_report/v1"
_BINDING_SCHEMA: Final[Literal["aegis.route_source_binding/v1"]] = "aegis.route_source_binding/v1"


class RouteSourceBinding(AegisModel):
    """Owner-authored map from a local service route to a source file."""

    schema_version: Literal["aegis.route_source_binding/v1"] = _BINDING_SCHEMA
    route_prefix: str = Field(min_length=1, max_length=256)
    source_file: str = Field(min_length=1, max_length=1024)

    @model_validator(mode="after")
    def _validate_binding(self) -> RouteSourceBinding:
        if (
            not self.route_prefix.startswith("/")
            or "?" in self.route_prefix
            or "#" in self.route_prefix
            or "%" in self.route_prefix
        ):
            raise ValueError("route_prefix must be a literal local path prefix")
        _relative_source_path(self.source_file)
        return self


class InvestigationHypothesis(AegisModel):
    """Evidence-linked lead, not a confirmed incident or causal finding."""

    schema_version: Literal["aegis.investigation_hypothesis/v1"] = _HYPOTHESIS_SCHEMA
    id: RecordId
    case_id: CaseId
    status: Literal["hypothesis"] = "hypothesis"
    event_id: RecordId
    finding_digest: Digest
    finding_tool: Literal["semgrep", "bandit"]
    finding_rule_id: str = Field(min_length=1)
    source_file: str = Field(min_length=1)
    source_line: int = Field(ge=0)
    deployment_source_digest: Digest
    evidence_refs: tuple[Uri, ...] = Field(min_length=3, max_length=3)
    summary: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def _require_case_scoped_artifact_refs(self) -> InvestigationHypothesis:
        prefix = f"artifact://{self.case_id}/sha256/"
        for reference in self.evidence_refs:
            if not reference.startswith(prefix):
                raise ValueError("hypothesis evidence references must be case-scoped artifacts")
            Digest(digest=reference.removeprefix(prefix))
        return self


class CorrelationReport(AegisModel):
    schema_version: Literal["aegis.correlation_report/v1"] = _REPORT_SCHEMA
    case_id: CaseId
    hypotheses: tuple[InvestigationHypothesis, ...]
    suspicious_events: int = Field(ge=0)
    correlated_pairs: int = Field(ge=0)
    warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _report_matches_hypotheses(self) -> CorrelationReport:
        if self.correlated_pairs != len(self.hypotheses):
            raise ValueError("correlated_pairs must equal the number of emitted hypotheses")
        if any(item.case_id != self.case_id for item in self.hypotheses):
            raise ValueError("all hypotheses must belong to the report case")
        return self


def _relative_source_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {".", ".."} for part in path.parts):
        raise ValueError("source_file must be a normalized relative path without traversal")
    normalized = path.as_posix()
    if normalized != value or "\\" in value:
        raise ValueError("source_file must use normalized POSIX relative-path syntax")
    return normalized


def _route_binding(path: str, bindings: tuple[RouteSourceBinding, ...]) -> str | None:
    request_path = path.split("?", maxsplit=1)[0].split("#", maxsplit=1)[0]
    matches = [
        binding
        for binding in bindings
        if request_path == binding.route_prefix
        or request_path.startswith(binding.route_prefix.rstrip("/") + "/")
    ]
    if not matches:
        return None
    longest = max(len(binding.route_prefix) for binding in matches)
    best = {binding.source_file for binding in matches if len(binding.route_prefix) == longest}
    return next(iter(best)) if len(best) == 1 else None


def _finding_digest(finding: NormalizedFinding) -> Digest:
    payload = finding.model_dump_json().encode("utf-8")
    return Digest(digest=hashlib.sha256(payload).hexdigest())


def correlate_evidence(
    *,
    case_id: CaseId,
    events: tuple[NormalizedEvent, ...],
    findings: tuple[NormalizedFinding, ...],
    bindings: tuple[RouteSourceBinding, ...],
    scan_source_digest: Digest,
    deployment: DeploymentProvenance,
    finding_evidence_ref: Uri,
    deployment_evidence_ref: Uri,
) -> CorrelationReport:
    """Create reproducible hypotheses from same-version, same-case evidence.

    Cross-case input is rejected rather than silently joined. A provenance
    mismatch returns no hypotheses. Route bindings are explicit trusted
    configuration; event paths and scanner messages are treated as data.
    """
    if deployment.case_id != case_id:
        raise ValueError("deployment provenance belongs to a different case")
    required_prefix = f"artifact://{case_id}/sha256/"
    for label, reference in (
        ("finding", finding_evidence_ref),
        ("deployment", deployment_evidence_ref),
    ):
        if not reference.startswith(required_prefix):
            raise ValueError(f"{label} evidence reference must be a case-scoped artifact URI")
        Digest(digest=reference.removeprefix(required_prefix))
    if any(event.case_id != case_id for event in events):
        raise ValueError("cross-case telemetry is not accepted for correlation")
    if scan_source_digest != deployment.source_commit_digest:
        return CorrelationReport(
            case_id=case_id,
            hypotheses=(),
            suspicious_events=sum(
                event.inferred_classification is EventClassification.SUSPICIOUS for event in events
            ),
            correlated_pairs=0,
            warnings=("scan_runtime_source_digest_mismatch",),
        )

    normalized_findings: list[tuple[str, NormalizedFinding, Digest]] = []
    warnings: list[str] = []
    for finding in findings:
        try:
            source_file = _relative_source_path(finding.file)
        except ValueError:
            warnings.append("finding_with_unusable_source_path_ignored")
            continue
        normalized_findings.append((source_file, finding, _finding_digest(finding)))

    hypotheses: list[InvestigationHypothesis] = []
    suspicious_events = [
        event for event in events if event.inferred_classification is EventClassification.SUSPICIOUS
    ]
    for event in suspicious_events:
        matched_source_file = _route_binding(event.path, bindings)
        if matched_source_file is None:
            continue
        for finding_file, finding, finding_digest in normalized_findings:
            if finding_file != matched_source_file:
                continue
            event_ref = f"artifact://{case_id}/sha256/{event.raw_digest.digest}"
            identity_material = "\0".join(
                (case_id, event.id, finding_digest.digest, deployment.source_commit_digest.digest)
            ).encode("utf-8")
            hypothesis_id = "hyp-" + hashlib.sha256(identity_material).hexdigest()[:32]
            hypotheses.append(
                InvestigationHypothesis(
                    id=hypothesis_id,
                    case_id=case_id,
                    event_id=event.id,
                    finding_digest=finding_digest,
                    finding_tool=finding.tool,
                    finding_rule_id=finding.rule_id,
                    source_file=matched_source_file,
                    source_line=finding.line,
                    deployment_source_digest=deployment.source_commit_digest,
                    evidence_refs=(event_ref, finding_evidence_ref, deployment_evidence_ref),
                    summary=(
                        "Suspicious telemetry maps to a source file with a static finding "
                        "in the deployed source version; causal relevance is unconfirmed."
                    ),
                )
            )

    return CorrelationReport(
        case_id=case_id,
        hypotheses=tuple(hypotheses),
        suspicious_events=len(suspicious_events),
        correlated_pairs=len(hypotheses),
        warnings=tuple(sorted(set(warnings))),
    )
