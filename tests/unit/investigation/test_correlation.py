from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from aegis.domain.base import Digest
from aegis.evidence.store import InMemoryArtifactStore
from aegis.investigation.correlation import (
    CorrelationReport,
    RouteSourceBinding,
    correlate_evidence,
)
from aegis.range.provenance import DeploymentProvenance
from aegis.telemetry.events import NormalizedEvent, parse_proxy_log_line
from aegis.tools.findings import NormalizedFinding


def _event(*, case_id: str = "AGE-0001", event_id: str = "evt-1", path: str) -> NormalizedEvent:
    line = json.dumps(
        {
            "ts": 1_760_000_000,
            "method": "GET",
            "path": path,
            "client": "range-client",
            "blocked": False,
            "status": 200,
        }
    )
    return parse_proxy_log_line(
        line,
        case_id=case_id,
        event_id=event_id,
        artifacts=InMemoryArtifactStore(),
    )


def _deployment(
    *, case_id: str = "AGE-0001", source_digest: str = "a" * 64
) -> DeploymentProvenance:
    return DeploymentProvenance(
        case_id=case_id,
        container_name="range-app",
        image_digest="sha256:" + "b" * 64,
        source_repository="owned-fixture",
        source_commit_digest=Digest(digest=source_digest),
        deployed_at=datetime.now(UTC),
    )


def _finding(file: str = "src/app.py") -> NormalizedFinding:
    return NormalizedFinding(
        tool="semgrep",
        rule_id="python.path-traversal",
        file=file,
        line=23,
        severity="HIGH",
        message="untrusted scanner message is not copied into the hypothesis",
    )


def _correlate(
    event: NormalizedEvent,
    *,
    scan_digest: str = "a" * 64,
    findings: tuple[NormalizedFinding, ...] | None = None,
    bindings: tuple[RouteSourceBinding, ...] | None = None,
    finding_ref: str = f"artifact://AGE-0001/sha256/{'d' * 64}",
    deployment_ref: str = f"artifact://AGE-0001/sha256/{'e' * 64}",
) -> CorrelationReport:
    return correlate_evidence(
        case_id="AGE-0001",
        events=(event,),
        findings=findings or (_finding(),),
        bindings=bindings
        or (RouteSourceBinding(route_prefix="/download", source_file="src/app.py"),),
        scan_source_digest=Digest(digest=scan_digest),
        deployment=_deployment(),
        finding_evidence_ref=finding_ref,
        deployment_evidence_ref=deployment_ref,
    )


def test_suspicious_event_correlates_only_with_explicit_route_and_same_source() -> None:
    report = _correlate(_event(path="/download?filename=../secret.txt"))
    assert report.suspicious_events == 1
    assert report.correlated_pairs == 1
    hypothesis = report.hypotheses[0]
    assert hypothesis.status == "hypothesis"
    assert hypothesis.source_file == "src/app.py"
    assert hypothesis.source_line == 23
    assert len(hypothesis.evidence_refs) == 3
    assert "causal relevance is unconfirmed" in hypothesis.summary
    assert "untrusted scanner message" not in hypothesis.summary


def test_benign_event_and_nonmatching_route_do_not_create_hypotheses() -> None:
    benign = _correlate(_event(path="/download?filename=welcome.txt"))
    unrelated = _correlate(_event(path="/downloads?filename=../secret.txt"))
    assert benign.hypotheses == ()
    assert unrelated.hypotheses == ()


def test_source_provenance_mismatch_fails_closed() -> None:
    report = _correlate(_event(path="/download?filename=../secret.txt"), scan_digest="c" * 64)
    assert report.hypotheses == ()
    assert report.warnings == ("scan_runtime_source_digest_mismatch",)


def test_evidence_links_must_be_case_scoped_content_addressed_artifacts() -> None:
    with pytest.raises(ValueError, match="case-scoped artifact URI"):
        _correlate(
            _event(path="/download?filename=../secret.txt"),
            finding_ref="finding://sha256/" + "d" * 64,
        )


def test_cross_case_telemetry_is_rejected() -> None:
    with pytest.raises(ValueError, match="cross-case"):
        _correlate(_event(case_id="AGE-OTHER", path="/download?filename=../secret.txt"))


def test_unsafe_source_paths_are_not_correlated() -> None:
    report = _correlate(
        _event(path="/download?filename=../secret.txt"),
        findings=(_finding("../outside.py"),),
    )
    assert report.hypotheses == ()
    assert report.warnings == ("finding_with_unusable_source_path_ignored",)


def test_route_mapping_rejects_traversal_source_path() -> None:
    with pytest.raises(ValueError, match="normalized relative path"):
        RouteSourceBinding(route_prefix="/download", source_file="../outside.py")
