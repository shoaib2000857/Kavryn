"""Semgrep and Bandit adapters: the Change 5 static-analysis workers.

Each is a ``ToolAdapter`` (docs/IMPLEMENTATION_HANDOFF.md Change 4) that
runs a pinned analysis-worker container (docs/DECISIONS.md ADR-023) with
no network and a read-only source mount
(docs/TOOLS_AND_SANDBOXES.md "Read-only analysis worker"), then
normalizes the tool's raw output while separately content-addressing
the raw output itself (docs/EVIDENCE_AND_ASSURANCE.md).

The container runner is dependency-injected (default: the real
``run_container``) so the adapter's own logic — parameter validation,
path resolution, command construction, result normalization — is fully
unit-testable without Docker; a genuine end-to-end run against the
pinned image and the project's own vulnerable fixture is exercised
separately in ``tests/integration``.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import PurePosixPath

from aegis.broker.adapter import AdapterDescriptor, AdapterResult, validate_parameters
from aegis.core.actions import (
    ActionDefinition,
    ActionParameter,
    ActionResources,
    ActionSideEffect,
    ActionValueType,
    VerificationContract,
)
from aegis.domain.action import ActionRequest
from aegis.evidence.store import ArtifactStore
from aegis.tools.findings import (
    FindingsParseError,
    NormalizedFinding,
    parse_bandit_json,
    parse_semgrep_json,
)
from aegis.workers.container import ContainerRunResult, ContainerRunSpec, resolve_read_only_source
from aegis.workers.container import run_container as _default_run_container

__all__ = ["ContainerStaticAnalysisAdapter", "make_bandit_adapter", "make_semgrep_adapter"]

_ALLOWED_PARAMETER_KEYS = frozenset({"source_dir"})


def _normalize_finding_path(path: str) -> str:
    """Convert a worker path into a safe path relative to its `/src` mount."""
    if path.startswith("/"):
        if not path.startswith("/src/"):
            raise FindingsParseError("scanner finding path is outside the /src mount")
        relative_path = path.removeprefix("/src/")
    else:
        relative_path = path
    parsed = PurePosixPath(relative_path)
    if (
        not parsed.parts
        or any(part in {".", ".."} for part in parsed.parts)
        or parsed.as_posix() != relative_path
        or "\\" in relative_path
    ):
        raise FindingsParseError("scanner finding path is not a normalized relative path")
    return parsed.as_posix()


class ContainerStaticAnalysisAdapter:
    """Runs one static-analysis tool inside the pinned analysis-worker image."""

    allowed_parameter_keys = _ALLOWED_PARAMETER_KEYS

    def __init__(
        self,
        descriptor: AdapterDescriptor,
        *,
        artifacts: ArtifactStore,
        allowed_source_root: str,
        image_ref: str,
        command: tuple[str, ...],
        output_parser: Callable[[str], tuple[NormalizedFinding, ...]],
        runner: Callable[[ContainerRunSpec], ContainerRunResult] = _default_run_container,
    ) -> None:
        self.descriptor = descriptor
        self.action_definitions: tuple[ActionDefinition, ...] = (
            ActionDefinition(
                action_type="scan.run",
                version=1,
                adapter_id=descriptor.id,
                description=f"Run the registered {descriptor.category} analysis adapter.",
                inputs=(
                    ActionParameter(
                        name="source_dir",
                        value_type=ActionValueType.STRING,
                        description="Authorized source directory mounted read-only.",
                    ),
                ),
                outputs=(
                    ActionParameter(
                        name="findings",
                        value_type=ActionValueType.ARRAY,
                        required=False,
                        description="Normalized security findings.",
                    ),
                    ActionParameter(
                        name="parse_error",
                        value_type=ActionValueType.BOOLEAN,
                        required=False,
                        description="Whether tool output parsing failed.",
                    ),
                ),
                risk_tier=descriptor.risk_tier,
                side_effects=(ActionSideEffect.READ,),
                filesystem="read-target",
                resources=ActionResources(
                    timeout_seconds=descriptor.limits.timeout_seconds,
                    cpu=descriptor.limits.cpu,
                    memory_mb=descriptor.limits.memory_mb,
                ),
                verification=VerificationContract(required=False),
                idempotent=True,
                max_retries=0,
            ),
        )
        self._artifacts = artifacts
        self._allowed_source_root = allowed_source_root
        self._image_ref = image_ref
        self._command = command
        self._output_parser = output_parser
        self._runner = runner
        self.calls: list[ActionRequest] = []

    def run(self, request: ActionRequest, *, capability_ref: str) -> AdapterResult:
        validate_parameters(
            self.descriptor.id, request.parameters, allowed_keys=self.allowed_parameter_keys
        )
        self.calls.append(request)

        resolved_source = resolve_read_only_source(
            request.parameters["source_dir"], allowed_root=self._allowed_source_root
        )
        spec = ContainerRunSpec(
            image=self._image_ref,
            command=self._command,
            read_only_mounts=((resolved_source, "/src"),),
            network="none",
            timeout_seconds=self.descriptor.limits.timeout_seconds,
            memory_mb=self.descriptor.limits.memory_mb,
            cpus=self.descriptor.limits.cpu,
        )
        result = self._runner(spec)
        raw_digest = self._artifacts.put(result.stdout.encode())

        if result.timed_out:
            return AdapterResult(
                exit_status="timeout",
                stdout_digest=raw_digest,
                duration_seconds=result.duration_seconds,
            )

        try:
            parsed_findings = self._output_parser(result.stdout)
            findings = tuple(
                NormalizedFinding(
                    **finding.model_dump(exclude={"file"}),
                    file=_normalize_finding_path(finding.file),
                )
                for finding in parsed_findings
            )
        except FindingsParseError:
            return AdapterResult(
                exit_status="failure",
                output={"parse_error": True},
                stdout_digest=raw_digest,
                duration_seconds=result.duration_seconds,
            )

        return AdapterResult(
            exit_status="success",
            output={"findings": [finding.model_dump(mode="json") for finding in findings]},
            stdout_digest=raw_digest,
            duration_seconds=result.duration_seconds,
        )


DEFAULT_SEMGREP_RULESET = "/opt/aegis/rules/python-security.yaml"
"""The in-image, offline pinned ruleset path (docker/analysis-worker/rules/).

The worker runs with ``--network none`` (SR-NET-001), so a
registry-fetched ruleset such as ``p/security-audit`` or ``auto`` would
simply hang until it times out — rules must be baked into the pinned
image itself (docs/TOOLS_AND_SANDBOXES.md's tool-descriptor convention
of ``ruleset_ref: immutable-artifact``), not fetched at scan time.
"""


def make_semgrep_adapter(
    descriptor: AdapterDescriptor,
    *,
    artifacts: ArtifactStore,
    allowed_source_root: str,
    image_ref: str,
    ruleset: str = DEFAULT_SEMGREP_RULESET,
    runner: Callable[[ContainerRunSpec], ContainerRunResult] = _default_run_container,
) -> ContainerStaticAnalysisAdapter:
    # --disable-version-check is required, not cosmetic: even with
    # --metrics=off, semgrep otherwise attempts a network version check
    # after scanning and before writing --json output, which hangs
    # until the adapter's own timeout under --network none. Found and
    # fixed while verifying this adapter against real Docker.
    return ContainerStaticAnalysisAdapter(
        descriptor,
        artifacts=artifacts,
        allowed_source_root=allowed_source_root,
        image_ref=image_ref,
        command=(
            "semgrep",
            "--config",
            ruleset,
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            "/src",
        ),
        output_parser=parse_semgrep_json,
        runner=runner,
    )


def make_bandit_adapter(
    descriptor: AdapterDescriptor,
    *,
    artifacts: ArtifactStore,
    allowed_source_root: str,
    image_ref: str,
    runner: Callable[[ContainerRunSpec], ContainerRunResult] = _default_run_container,
) -> ContainerStaticAnalysisAdapter:
    return ContainerStaticAnalysisAdapter(
        descriptor,
        artifacts=artifacts,
        allowed_source_root=allowed_source_root,
        image_ref=image_ref,
        command=("bandit", "-r", "-f", "json", "/src"),
        output_parser=parse_bandit_json,
        runner=runner,
    )
