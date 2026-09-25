"""Typed, case-bound deployment adapter for the owned Docker cyber range.

This adapter is intentionally narrow: it can build only from one configured
fixture, modify only configured source files, and replace one configured
container on one configured Docker network. The reasoning process receives no
Docker command, socket, or arbitrary image selector. Build and rollout are one
R4 transaction so independent postconditions can trigger a brokered rollback.

This is a local research-range adapter, not a production deployment backend.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from aegis.broker.adapter import (
    AdapterDescriptor,
    AdapterLimits,
    AdapterPermissions,
    AdapterResult,
    ParameterValidationError,
    ToolAdapter,
    validate_parameters,
)
from aegis.core.actions import (
    ActionDefinition,
    ActionParameter,
    ActionResources,
    ActionSideEffect,
    VerificationContract,
)
from aegis.domain.action import ActionRequest
from aegis.domain.base import Digest
from aegis.domain.policy import RiskTier
from aegis.range.containment import ContainmentRule, read_rules, write_rules
from aegis.range.docker_cmd import CommandRunner, DockerCommandError, default_runner
from aegis.range.service import ServiceSpec, start_service
from aegis.repair.candidate import DiffPolicyError, validate_diff_policy

__all__ = ["RangeDeploymentAdapter"]

Probe = Callable[[], bool]


class RangeDeploymentAdapter(ToolAdapter):
    """Build and roll out one verified diff; restore the previous range on rollback."""

    descriptor = AdapterDescriptor(
        id="range.deployment",
        version=1,
        category="authorized-local-range-deployment",
        permissions=AdapterPermissions(
            filesystem="read-write-workspace", docker_control="authorized-range"
        ),
        risk_tier=RiskTier.R4_CHANGE,
        limits=AdapterLimits(timeout_seconds=600, cpu=2.0, memory_mb=2048),
        parser="aegis-range-deployment-v1",
    )
    action_definitions = (
        ActionDefinition(
            action_type="deployment.rollout",
            version=1,
            adapter_id="range.deployment",
            description="Build and roll out an allowlisted patch to the owned local range.",
            inputs=(
                ActionParameter(
                    name="operation", value_type="string", description="Fixed apply operation."
                ),
                ActionParameter(
                    name="candidate_diff", value_type="string", description="Candidate source diff."
                ),
                ActionParameter(
                    name="diff_digest", value_type="string", description="SHA-256 of the diff."
                ),
                ActionParameter(
                    name="base_source_digest",
                    value_type="string",
                    description="Trusted base source SHA-256.",
                ),
            ),
            outputs=(
                ActionParameter(
                    name="operation",
                    value_type="string",
                    required=False,
                    description="Operation result.",
                ),
                ActionParameter(
                    name="image_id",
                    value_type="string",
                    required=False,
                    description="Built image identifier.",
                ),
                ActionParameter(
                    name="changed_files",
                    value_type="array",
                    required=False,
                    description="Changed allowlisted files.",
                ),
                ActionParameter(
                    name="error_type",
                    value_type="string",
                    required=False,
                    description="Failure class, if any.",
                ),
                ActionParameter(
                    name="error",
                    value_type="string",
                    required=False,
                    description="Bounded failure summary.",
                ),
                ActionParameter(
                    name="baseline_restored",
                    value_type="boolean",
                    required=False,
                    description="Whether failed rollout restored baseline.",
                ),
            ),
            risk_tier=RiskTier.R4_CHANGE,
            side_effects=(ActionSideEffect.WRITE, ActionSideEffect.DEPLOYMENT),
            filesystem="read-write-workspace",
            reversible=True,
            rollback_action_type="deployment.rollback",
            resources=ActionResources(timeout_seconds=600, cpu=2, memory_mb=2048),
            verification=VerificationContract(required=True, verifier_id="verifier:range-probes"),
        ),
        ActionDefinition(
            action_type="deployment.rollback",
            version=1,
            adapter_id="range.deployment",
            description="Restore the prior image and containment state in the owned local range.",
            inputs=(
                ActionParameter(
                    name="operation", value_type="string", description="Fixed rollback operation."
                ),
                ActionParameter(
                    name="rollback_of",
                    value_type="string",
                    description="Rollout request identifier.",
                ),
            ),
            outputs=(
                ActionParameter(
                    name="operation",
                    value_type="string",
                    required=False,
                    description="Operation result.",
                ),
                ActionParameter(
                    name="restored",
                    value_type="boolean",
                    required=False,
                    description="Whether previous state is restored.",
                ),
            ),
            risk_tier=RiskTier.R4_CHANGE,
            side_effects=(ActionSideEffect.WRITE, ActionSideEffect.DEPLOYMENT),
            filesystem="read-write-workspace",
            resources=ActionResources(timeout_seconds=600, cpu=2, memory_mb=2048),
            verification=VerificationContract(required=True, verifier_id="verifier:range-probes"),
        ),
    )
    allowed_parameter_keys = frozenset(
        {"operation", "candidate_diff", "diff_digest", "base_source_digest", "rollback_of"}
    )

    def __init__(
        self,
        *,
        fixture_dir: str,
        source_subdirectory: str,
        allowed_files: frozenset[str],
        base_source_digest: Digest,
        base_image: str,
        service: ServiceSpec,
        target_ref: str,
        rules_file: str,
        readiness_probe: Probe,
        runner: CommandRunner = default_runner,
    ) -> None:
        self._fixture_dir = Path(fixture_dir).resolve()
        self._source_subdirectory = source_subdirectory
        self._allowed_files = allowed_files
        self._base_source_digest = base_source_digest.digest
        self._base_image = base_image
        self._service = service
        self._target_ref = target_ref
        self._rules_file = rules_file
        self._readiness_probe = readiness_probe
        self._runner = runner
        self._deployment_states: dict[str, tuple[str, ContainmentRule]] = {}

        source_dir = (self._fixture_dir / source_subdirectory).resolve()
        if self._fixture_dir not in source_dir.parents:
            raise ValueError("source_subdirectory must remain inside fixture_dir")
        if not self._fixture_dir.is_dir() or not source_dir.is_dir():
            raise ValueError("fixture and source directories must exist")
        if not allowed_files or any(
            Path(item).is_absolute() or ".." in Path(item).parts for item in allowed_files
        ):
            raise ValueError("allowed_files must contain safe relative paths")
        if service.image != base_image:
            raise ValueError("service image must equal the configured base image")

    def run(self, request: ActionRequest, *, capability_ref: str) -> AdapterResult:
        del capability_ref  # The broker checks authority; the adapter checks only operation shape.
        validate_parameters(
            self.descriptor.id, request.parameters, allowed_keys=self.allowed_parameter_keys
        )
        if request.adapter != self.descriptor.id or request.target_ref != self._target_ref:
            raise ParameterValidationError(
                "deployment request is not bound to this configured range"
            )

        operation = request.parameters.get("operation")
        started = time.monotonic()
        if operation == "apply" and request.action_type == "deployment.rollout":
            return self._apply(request, started=started)
        if operation == "rollback" and request.action_type == "deployment.rollback":
            return self._rollback(request, started=started)
        raise ParameterValidationError("operation/action_type pair is not supported")

    def _apply(self, request: ActionRequest, *, started: float) -> AdapterResult:
        diff = request.parameters.get("candidate_diff")
        diff_digest = request.parameters.get("diff_digest")
        base_digest = request.parameters.get("base_source_digest")
        if not isinstance(diff, str) or not isinstance(diff_digest, str):
            raise ParameterValidationError("deployment requires a candidate diff and its digest")
        if base_digest != self._base_source_digest:
            raise ParameterValidationError(
                "candidate base digest does not match trusted range source"
            )
        calculated_digest = hashlib.sha256(diff.encode()).hexdigest()
        if diff_digest != calculated_digest:
            raise ParameterValidationError("candidate diff digest mismatch")
        try:
            changed = validate_diff_policy(diff, allowed_files=self._allowed_files)
        except DiffPolicyError as exc:
            raise ParameterValidationError(f"candidate diff failed policy: {exc}") from exc
        if not changed:
            raise ParameterValidationError("candidate diff contains no authorized source changes")

        previous_rules = read_rules(self._rules_file)
        tag = f"aegis-range-patch-{calculated_digest[:20]}"
        try:
            image_id = self._build_candidate_image(diff=diff, tag=tag)
            self._replace_service(image_id)
            # Containment is removed only after the new service starts; the
            # independent transaction verifier then checks both attack and
            # benign behavior against the patched application.
            write_rules(self._rules_file, ContainmentRule())
            if not self._wait_until_ready():
                raise DockerCommandError("deployed range did not pass its readiness probe")
        except Exception as exc:
            restored = self._restore(self._base_image, previous_rules)
            return AdapterResult(
                exit_status="failure",
                output={
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:500],
                    "baseline_restored": restored,
                },
                duration_seconds=max(0.0, time.monotonic() - started),
            )

        self._deployment_states[request.id] = (self._base_image, previous_rules)
        return AdapterResult(
            exit_status="success",
            output={"operation": "apply", "image_id": image_id, "changed_files": list(changed)},
            duration_seconds=max(0.0, time.monotonic() - started),
        )

    def _rollback(self, request: ActionRequest, *, started: float) -> AdapterResult:
        rollback_of = request.parameters.get("rollback_of")
        if not isinstance(rollback_of, str):
            raise ParameterValidationError("rollback requires rollback_of")
        prior = self._deployment_states.get(rollback_of)
        if prior is None:
            raise ParameterValidationError("rollback_of does not identify a completed deployment")
        image_id, previous_rules = prior
        restored = self._restore(image_id, previous_rules)
        if not restored:
            return AdapterResult(
                exit_status="failure",
                output={"operation": "rollback", "restored": False},
                duration_seconds=max(0.0, time.monotonic() - started),
            )
        del self._deployment_states[rollback_of]
        return AdapterResult(
            exit_status="success",
            output={"operation": "rollback", "restored": True},
            duration_seconds=max(0.0, time.monotonic() - started),
        )

    def _build_candidate_image(self, *, diff: str, tag: str) -> str:
        with tempfile.TemporaryDirectory(prefix="aegis-range-deploy-") as temporary:
            root = Path(temporary) / "fixture"
            root.mkdir()
            shutil.copy2(self._fixture_dir / "Dockerfile", root / "Dockerfile")
            shutil.copy2(self._fixture_dir / "requirements.txt", root / "requirements.txt")
            shutil.copytree(
                self._fixture_dir / self._source_subdirectory, root / self._source_subdirectory
            )
            source = (root / self._source_subdirectory).resolve()
            if root.resolve() not in source.parents:
                raise ParameterValidationError("source path escaped the temporary fixture")
            diff_path = Path(temporary) / "candidate.diff"
            diff_path.write_text(diff)
            self._apply_diff(source=source, diff_path=diff_path)
            dockerfile = root / "Dockerfile"
            result = self._runner(
                ["docker", "build", "--network=none", "-t", tag, "-f", str(dockerfile), str(root)]
            )
            if result.returncode != 0:
                raise DockerCommandError(f"candidate image build failed: {result.stderr[:1000]}")
            inspected = self._runner(["docker", "inspect", tag, "--format={{.Id}}"])
            if inspected.returncode != 0 or not inspected.stdout.strip().startswith("sha256:"):
                raise DockerCommandError("candidate image did not resolve to an immutable image id")
            return inspected.stdout.strip()

    def _apply_diff(self, *, source: Path, diff_path: Path) -> None:
        # patch uses argv (never a shell), operates only in a disposable copy,
        # and is constrained by the parsed diff allowlist above.
        result = subprocess.run(
            ["patch", "--strip=1", "--forward", "--input", str(diff_path)],
            cwd=source,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            raise DockerCommandError(
                f"verified candidate did not apply cleanly: {result.stderr[:1000]}"
            )

    def _replace_service(self, image: str) -> None:
        stopped = self._runner(["docker", "rm", "-f", self._service.name])
        if stopped.returncode != 0:
            raise DockerCommandError(
                f"failed to stop current range service: {stopped.stderr[:1000]}"
            )
        start_service(self._service.model_copy(update={"image": image}), runner=self._runner)

    def _restore(self, image: str, rules: ContainmentRule) -> bool:
        try:
            stopped = self._runner(["docker", "rm", "-f", self._service.name])
            # During a failed first start, the container may not exist. In
            # that case, continue with restoration rather than masking it.
            del stopped
            start_service(self._service.model_copy(update={"image": image}), runner=self._runner)
            write_rules(self._rules_file, rules)
            return self._wait_until_ready()
        except Exception:
            return False

    def _wait_until_ready(self, *, attempts: int = 20, delay_seconds: float = 0.5) -> bool:
        for _ in range(attempts):
            if self._readiness_probe():
                return True
            time.sleep(delay_seconds)
        return False
