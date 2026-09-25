"""Read a bounded tail of one configured local-range proxy's container logs.

This adapter is observation-only. It never accepts a container name, command,
or log selector from the model; the container and case service target are
trusted configuration and every read is brokered/audited.
"""

from __future__ import annotations

import subprocess
import time

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
from aegis.domain.policy import RiskTier
from aegis.range.docker_cmd import DockerCommandError

__all__ = ["ProxyLogsAdapter"]

_MAX_LOG_BYTES = 512 * 1024
_TAIL_LINES = "200"


class ProxyLogsAdapter(ToolAdapter):
    """Expose only bounded logs from the proxy fixed at adapter construction."""

    descriptor = AdapterDescriptor(
        id="range.proxy.logs",
        version=1,
        category="authorized-local-range-telemetry",
        permissions=AdapterPermissions(filesystem="none", docker_control="authorized-range"),
        risk_tier=RiskTier.R0_OBSERVE,
        limits=AdapterLimits(timeout_seconds=10, cpu=0.5, memory_mb=128),
        parser="bounded-proxy-log-tail-v1",
    )
    action_definitions = (
        ActionDefinition(
            action_type="telemetry.read",
            version=1,
            adapter_id="range.proxy.logs",
            description="Read a bounded telemetry tail from the configured local range proxy.",
            inputs=(),
            outputs=(
                ActionParameter(
                    name="logs",
                    value_type="string",
                    required=True,
                    description="Bounded untrusted proxy-log text.",
                ),
            ),
            risk_tier=RiskTier.R0_OBSERVE,
            side_effects=(ActionSideEffect.READ,),
            filesystem="none",
            resources=ActionResources(timeout_seconds=10, cpu=0.5, memory_mb=128),
            verification=VerificationContract(required=False, verifier_id=None),
        ),
    )
    allowed_parameter_keys = frozenset()

    def __init__(self, *, container_name: str, target_ref: str) -> None:
        if not container_name or container_name.startswith("-"):
            raise ValueError("container_name must be a configured container identifier")
        if not target_ref.startswith("service://"):
            raise ValueError("target_ref must identify the configured local range service")
        self._container_name = container_name
        self._target_ref = target_ref

    def run(self, request: ActionRequest, *, capability_ref: str) -> AdapterResult:
        del capability_ref  # The broker enforces authority and single-use semantics.
        validate_parameters(
            self.descriptor.id,
            request.parameters,
            allowed_keys=self.allowed_parameter_keys,
        )
        if (
            request.action_type != "telemetry.read"
            or request.adapter != self.descriptor.id
            or request.target_ref != self._target_ref
        ):
            raise ParameterValidationError("telemetry read is not bound to this configured range")

        started = time.monotonic()
        try:
            completed = subprocess.run(
                ["docker", "logs", "--tail", _TAIL_LINES, self._container_name],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            partial = _decode(exc.stdout)
            return AdapterResult(
                exit_status="timeout",
                output={"logs": _bounded_tail(partial)},
                duration_seconds=max(0.0, time.monotonic() - started),
            )
        except OSError as exc:
            raise DockerCommandError(f"failed to read configured proxy logs: {exc}") from exc
        logs = _bounded_tail(completed.stdout)
        if completed.returncode != 0:
            return AdapterResult(
                exit_status="failure",
                output={"logs": logs, "error": completed.stderr[:500]},
                duration_seconds=max(0.0, time.monotonic() - started),
            )
        return AdapterResult(
            exit_status="success",
            output={"logs": logs},
            duration_seconds=max(0.0, time.monotonic() - started),
        )


def _decode(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def _bounded_tail(value: str) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) > _MAX_LOG_BYTES:
        encoded = encoded[-_MAX_LOG_BYTES:]
        newline = encoded.find(b"\n")
        if newline >= 0:
            encoded = encoded[newline + 1 :]
    return encoded.decode("utf-8", errors="replace")
