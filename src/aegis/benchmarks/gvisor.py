"""Fixed evaluator plans under rootless gVisor and user-systemd resource limits.

This is an opt-in Linux benchmark adapter, not a generic shell tool. Plans and
scripts are prepared by the trusted evaluator; an agent can select only a plan ID.
No benchmark process receives host mounts, credentials, or a Docker socket.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from aegis.broker.adapter import (
    AdapterDescriptor,
    AdapterLimits,
    AdapterPermissions,
    AdapterResult,
    ParameterValidationError,
    validate_parameters,
)
from aegis.core.actions import (
    ActionDefinition,
    ActionParameter,
    ActionResources,
    ActionSideEffect,
    ActionValueType,
    VerificationContract,
)
from aegis.domain.action import ActionRequest
from aegis.domain.policy import RiskTier
from aegis.evidence.store import sha256_digest


@dataclass(frozen=True)
class EvaluationPlan:
    """Operator-owned plan; never deserialize this object from model output."""

    rootfs: Path
    script_name: str
    script_digest: str
    target_ref: str

    def validate(self) -> Path:
        if self.rootfs.is_symlink() or not self.rootfs.is_dir():
            raise ParameterValidationError("rootfs must be an existing non-symlink directory")
        root = self.rootfs.resolve()
        if root == Path("/") or root == Path.home():
            raise ParameterValidationError("host root/home is not a benchmark filesystem")
        if not self.script_name.isascii() or not self.script_name.replace("-", "").isalnum():
            raise ParameterValidationError("invalid fixed evaluator script name")
        script = root / "aegis-eval" / f"{self.script_name}.sh"
        if script.is_symlink() or not script.is_file() or not script.resolve().is_relative_to(root):
            raise ParameterValidationError("evaluator script is missing or escapes rootfs")
        if sha256_digest(script.read_bytes()).digest != self.script_digest:
            raise ParameterValidationError("evaluator script digest mismatch")
        return root


class GVisorEvaluationAdapter:
    """One fixed script per plan, with fail-closed parameter/target/hash checks.

    systemd must provide delegated user cgroups. Failure to launch is failure,
    never a fallback to host execution. Each run gets a fresh memory overlay.
    """

    descriptor = AdapterDescriptor(
        id="benchmark.gvisor",
        version=1,
        category="offline-benchmark-evaluation",
        permissions=AdapterPermissions(filesystem="read-write-workspace"),
        risk_tier=RiskTier.R2_VALIDATE,
        limits=AdapterLimits(timeout_seconds=300, cpu=2, memory_mb=3072),
        parser="bounded-evaluator-log-v1",
    )
    allowed_parameter_keys = frozenset({"plan_id"})
    action_definitions: tuple[ActionDefinition, ...] = (
        ActionDefinition(
            action_type="test.run",
            version=1,
            adapter_id="benchmark.gvisor",
            description="Run a fixed offline evaluator in an ephemeral rootless gVisor overlay.",
            inputs=(
                ActionParameter(
                    name="plan_id",
                    value_type=ActionValueType.STRING,
                    description="Operator-prepared immutable evaluator plan identifier.",
                ),
            ),
            outputs=tuple(
                ActionParameter(name=name, value_type=kind, description=description)
                for name, kind, description in (
                    ("exit_code", ActionValueType.INTEGER, "Exit code; -1 when unavailable."),
                    ("log", ActionValueType.STRING, "Bounded evaluator output."),
                    ("log_truncated", ActionValueType.BOOLEAN, "Output bound reached."),
                    ("timed_out", ActionValueType.BOOLEAN, "Controller runtime bound reached."),
                    ("plan_id", ActionValueType.STRING, "Evaluated fixed plan."),
                    ("network", ActionValueType.STRING, "Enforced network mode."),
                    ("rootless", ActionValueType.BOOLEAN, "Rootless execution requested."),
                )
            ),
            risk_tier=RiskTier.R2_VALIDATE,
            side_effects=(ActionSideEffect.WRITE,),
            filesystem="read-write-workspace",
            resources=ActionResources(timeout_seconds=300, cpu=2, memory_mb=3072),
            verification=VerificationContract(required=False),
        ),
    )

    def __init__(self, *, runsc: Path, state_root: Path, plans: dict[str, EvaluationPlan]) -> None:
        self._runsc = runsc.resolve(strict=True)
        self._state_root = state_root.resolve(strict=True)
        self._plans = dict(plans)

    def command(self, plan: EvaluationPlan, unit: str) -> list[str]:
        root = plan.validate()
        return [
            "/usr/bin/systemd-run",
            "--user",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            f"--unit={unit}",
            "--property=MemoryMax=3072M",
            "--property=CPUQuota=200%",
            "--property=TasksMax=256",
            "--property=RuntimeMaxSec=300",
            "/usr/bin/env",
            "-i",
            "PATH=/usr/bin:/bin",
            str(self._runsc),
            f"--root={self._state_root}",
            "--rootless",
            "--network=none",
            "do",
            f"--root={root}",
            "--cwd=/",
            "--force-overlay=true",
            "/bin/bash",
            f"/aegis-eval/{plan.script_name}.sh",
        ]

    def run(self, request: ActionRequest, *, capability_ref: str) -> AdapterResult:
        if not capability_ref:
            raise ParameterValidationError("broker capability required")
        validate_parameters(
            self.descriptor.id, request.parameters, allowed_keys=self.allowed_parameter_keys
        )
        plan_id = request.parameters.get("plan_id")
        if not isinstance(plan_id, str) or plan_id not in self._plans:
            raise ParameterValidationError("unknown evaluator plan")
        plan = self._plans[plan_id]
        if request.action_type != "test.run" or request.target_ref != plan.target_ref:
            raise ParameterValidationError("evaluator action/target mismatch")
        unit = f"aegis-eval-{uuid4().hex}"
        command = self.command(plan, unit)
        # Only the controller needs the user service bus. env -i above removes
        # even these variables from runsc and the guest process.
        environment = {"PATH": "/usr/bin:/bin"}
        for key in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
            if key in os.environ:
                environment[key] = os.environ[key]
        started = time.monotonic()
        timed_out = False
        code: int | None = None
        oversized = False
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(
                command,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
            while process.poll() is None:
                oversized = os.fstat(output.fileno()).st_size > 4_194_304
                timed_out = time.monotonic() - started > 310
                if oversized or timed_out:
                    break
                time.sleep(0.2)
            if oversized or timed_out:
                subprocess.run(
                    ["/usr/bin/systemctl", "--user", "stop", f"{unit}.service"],
                    env=environment,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                    check=False,
                )
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            code = process.returncode
            output.seek(0)
            raw = output.read(4_194_305)
        oversized = oversized or len(raw) > 4_194_304
        log = raw[:4_194_304].decode("utf-8", errors="replace")
        return AdapterResult(
            exit_status=(
                "timeout" if timed_out else "success" if code == 0 and not oversized else "failure"
            ),
            output={
                "exit_code": code if code is not None else -1,
                "log": log,
                "log_truncated": oversized,
                "timed_out": timed_out,
                "plan_id": plan_id,
                "network": "none",
                "rootless": True,
            },
            stdout_digest=sha256_digest(raw),
            duration_seconds=time.monotonic() - started,
        )
