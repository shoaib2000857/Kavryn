"""Brokered evidence collection for the owned path-traversal reference range.

This is a scenario-specific application service, not a generic SOC connector.
It performs a typed brokered Semgrep scan, reads a bounded tail of the configured
local proxy's logs, records deployment provenance, and returns hypotheses only.
The route/source binding and container identities are trusted configuration.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from aegis.broker.adapter import AdapterDescriptor, AdapterLimits, AdapterPermissions
from aegis.broker.broker import ActionBroker
from aegis.broker.registry import AdapterRegistry
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole, AwareDatetime
from aegis.domain.case import Case
from aegis.domain.policy import RiskTier
from aegis.domain.scope import ScopePolicy
from aegis.evidence.store import ArtifactStore
from aegis.investigation.correlation import (
    CorrelationReport,
    RouteSourceBinding,
    correlate_evidence,
)
from aegis.range.provenance import DeploymentProvenance
from aegis.repair.hashing import hash_source_tree
from aegis.telemetry.events import parse_proxy_log_line
from aegis.tools.findings import NormalizedFinding
from aegis.tools.static_analysis import ContainerStaticAnalysisAdapter, make_semgrep_adapter

__all__ = ["RangeEvidenceInvestigator", "make_range_semgrep_adapter"]


def make_range_semgrep_adapter(
    *,
    artifacts: ArtifactStore,
    fixture_dir: Path,
    analysis_image: str,
) -> ContainerStaticAnalysisAdapter:
    """Bind the scanner to the fixture root and a pinned worker image."""
    return make_semgrep_adapter(
        AdapterDescriptor(
            id="semgrep.scan",
            version=1,
            category="static-analysis",
            permissions=AdapterPermissions(filesystem="read-target"),
            risk_tier=RiskTier.R1_ANALYZE,
            limits=AdapterLimits(timeout_seconds=90, cpu=2.0, memory_mb=1536),
            parser="semgrep-json-v1",
        ),
        artifacts=artifacts,
        allowed_source_root=str(fixture_dir),
        image_ref=analysis_image,
    )


class RangeEvidenceInvestigator:
    """Gather and correlate evidence for the configured local reference range."""

    def __init__(
        self,
        *,
        registry: AdapterRegistry,
        broker: ActionBroker,
        case: Case,
        scope: ScopePolicy,
        artifacts: ArtifactStore,
        fixture_dir: Path,
        source_dir: Path,
        app_image: str,
        app_container: str,
        target_ref: str,
        now: AwareDatetime,
        route_source_bindings: tuple[RouteSourceBinding, ...] = (
            RouteSourceBinding(route_prefix="/download", source_file="app.py"),
        ),
    ) -> None:
        """Capture trusted case configuration; never accept these from model output."""
        if broker.action_definition("scan.run").adapter_id != "semgrep.scan":
            raise ValueError("the broker's scan.run action is not bound to semgrep.scan")
        if broker.action_definition("telemetry.read").adapter_id != "range.proxy.logs":
            raise ValueError("the broker's telemetry.read action is not bound to range.proxy.logs")
        if registry.get("semgrep.scan").descriptor.id != "semgrep.scan":
            raise ValueError("the Semgrep adapter registration is inconsistent")
        if registry.get("range.proxy.logs").descriptor.id != "range.proxy.logs":
            raise ValueError("the proxy-log adapter registration is inconsistent")
        if case.id != scope.case_id:
            raise ValueError("case and scope must identify the same case")
        trusted_fixture = fixture_dir.resolve()
        trusted_source = source_dir.resolve()
        if trusted_source != trusted_fixture and trusted_fixture not in trusted_source.parents:
            raise ValueError("source directory must remain inside the configured range fixture")
        if not trusted_fixture.is_dir() or not trusted_source.is_dir():
            raise ValueError("range fixture and source directories must exist")
        if not app_image.startswith("sha256:"):
            raise ValueError("deployment provenance requires an immutable image digest")
        self._broker = broker
        self._case = case
        self._scope = scope
        self._artifacts = artifacts
        self._fixture_dir = trusted_fixture
        self._source_dir = trusted_source
        self._app_image = app_image
        self._app_container = app_container
        self._target_ref = target_ref
        self._now = now
        if not route_source_bindings:
            raise ValueError("at least one trusted route-to-source binding is required")
        self._route_source_bindings = route_source_bindings

    def __call__(self) -> CorrelationReport:
        """Run a scoped scan and correlate it with bounded local telemetry."""
        request = ActionRequest(
            id=f"investigation-scan-{uuid4().hex}",
            case_id=self._case.id,
            actor_id="control:investigator",
            role=ActorRole.CONTROL_PLANE,
            action_type="scan.run",
            target_ref=self._target_ref,
            adapter="semgrep.scan",
            parameters={"source_dir": str(self._source_dir)},
            expected_evidence=("normalized_findings", "scanner_output_digest"),
            reason="Run the registered offline scanner against the in-scope range source.",
            requested_at=self._now,
        )
        scan = self._broker.submit(
            request,
            case=self._case,
            scope=self._scope,
            now=self._now,
            decision_id=f"investigation-decision-{uuid4().hex}",
            policy_version="range-scope-v1",
        )
        if scan.decision.outcome.value != "permitted" or scan.result is None:
            raise RuntimeError("broker did not permit the scoped static-analysis action")
        if scan.result.exit_status != "success":
            raise RuntimeError("static-analysis worker did not produce a valid result")
        if not scan.transaction.output_artifacts:
            raise RuntimeError("broker did not retain the normalized scanner result artifact")
        raw_findings = scan.result.output.get("findings")
        if not isinstance(raw_findings, list):
            raise RuntimeError("static-analysis result omitted normalized findings")
        findings = tuple(NormalizedFinding.model_validate(item) for item in raw_findings)

        telemetry_request = ActionRequest(
            id=f"investigation-telemetry-{uuid4().hex}",
            case_id=self._case.id,
            actor_id="control:investigator",
            role=ActorRole.CONTROL_PLANE,
            action_type="telemetry.read",
            target_ref=self._target_ref,
            adapter="range.proxy.logs",
            parameters={},
            expected_evidence=("bounded_proxy_logs",),
            reason="Read bounded telemetry from the configured local range proxy.",
            requested_at=self._now,
        )
        telemetry = self._broker.submit(
            telemetry_request,
            case=self._case,
            scope=self._scope,
            now=self._now,
            decision_id=f"telemetry-decision-{uuid4().hex}",
            policy_version="range-scope-v1",
        )
        if telemetry.decision.outcome.value != "permitted" or telemetry.result is None:
            raise RuntimeError("broker did not permit the in-scope telemetry read")
        if telemetry.result.exit_status != "success":
            raise RuntimeError("configured range telemetry could not be read")
        logs = telemetry.result.output.get("logs")
        if not isinstance(logs, str):
            raise RuntimeError("telemetry adapter omitted its bounded log output")
        events = tuple(
            parse_proxy_log_line(
                line,
                case_id=self._case.id,
                event_id=f"proxy-event-{index}",
                artifacts=self._artifacts,
                suspicious_path_prefixes=tuple(
                    binding.route_prefix for binding in self._route_source_bindings
                ),
            )
            for index, line in enumerate(logs.splitlines())
            if line.startswith("{")
        )
        source_digest = hash_source_tree(self._source_dir)
        deployment = DeploymentProvenance(
            case_id=self._case.id,
            container_name=self._app_container,
            image_digest=self._app_image,
            source_repository=self._fixture_dir.name,
            source_commit_digest=source_digest,
            deployed_at=self._now,
        )
        deployment_evidence_ref = self._broker.record_evidence_artifact(
            case_id=self._case.id,
            content=deployment.model_dump_json().encode("utf-8"),
            now=self._now,
            producer="control:investigator",
        )
        return correlate_evidence(
            case_id=self._case.id,
            events=events,
            findings=findings,
            bindings=self._route_source_bindings,
            scan_source_digest=source_digest,
            deployment=deployment,
            finding_evidence_ref=(
                f"artifact://{self._case.id}/sha256/{scan.transaction.output_artifacts[-1].digest}"
            ),
            deployment_evidence_ref=deployment_evidence_ref,
        )
