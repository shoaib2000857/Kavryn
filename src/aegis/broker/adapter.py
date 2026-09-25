"""The typed tool adapter contract.

See docs/TOOLS_AND_SANDBOXES.md "Tool descriptor" and "Worker classes",
and docs/ARCHITECTURE.md's "Tool adapter" row ("Converts typed request
to a fixed command/API operation | Narrow trusted computing base").

``AdapterDescriptor`` is the *full* execution descriptor — "Only the
broker sees the full execution descriptor" — distinct from
``aegis.providers.schemas.ToolDescriptor``, the filtered description
shown to the model.

There is deliberately no generic/free-form command field anywhere in
this module (ADR-006): every adapter validates its own fixed set of
recognized parameter keys before doing anything else.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol

from pydantic import Field

from aegis.core.actions import ActionDefinition
from aegis.domain.action import ActionRequest
from aegis.domain.base import AegisModel, Digest, ToolId
from aegis.domain.policy import RiskTier

__all__ = [
    "AdapterDescriptor",
    "AdapterLimits",
    "AdapterPermissions",
    "AdapterResult",
    "ParameterValidationError",
    "ToolAdapter",
    "validate_parameters",
]


class AdapterLimits(AegisModel):
    timeout_seconds: int = Field(gt=0)
    cpu: float = Field(gt=0)
    memory_mb: int = Field(gt=0)


class AdapterPermissions(AegisModel):
    """Declared privileges for one adapter.

    ``network`` and ``secrets`` only accept ``"none"`` for this change:
    every worker class available so far (the in-process mock) has
    neither network nor secret access, so no other value could be
    honest yet. This is expected to widen in a later change alongside a
    worker class that actually has network or secret access, not before.
    """

    filesystem: Literal["none", "read-target", "read-write-workspace"]
    network: Literal["none"] = "none"
    secrets: Literal["none"] = "none"
    docker_control: Literal["none", "authorized-range"] = "none"


class AdapterDescriptor(AegisModel):
    """The full, broker-only execution descriptor for one typed adapter."""

    id: ToolId
    version: int = Field(ge=1)
    category: str = Field(min_length=1, max_length=100)
    permissions: AdapterPermissions
    risk_tier: RiskTier
    limits: AdapterLimits
    parser: str = Field(min_length=1, max_length=100)


class AdapterResult(AegisModel):
    """The typed, structured outcome of one adapter run.

    Success, failure, and timeout are all ordinary data here, never
    exceptions crossing the broker boundary — the broker always gets a
    well-formed result to audit, whatever happened.
    """

    exit_status: Literal["success", "failure", "timeout"]
    output: dict[str, Any] = Field(default_factory=dict)
    stdout_digest: Digest | None = None
    duration_seconds: float = Field(ge=0)


class ParameterValidationError(ValueError):
    """Raised when a request's parameters include an unrecognized key.

    docs/TOOLS_AND_SANDBOXES.md "Command construction": "reject unknown
    options." Every adapter enforces this against its own fixed
    parameter set before doing anything else.
    """


def validate_parameters(
    adapter_id: str, parameters: dict[str, Any], *, allowed_keys: frozenset[str]
) -> None:
    unknown = set(parameters) - allowed_keys
    if unknown:
        raise ParameterValidationError(
            f"adapter '{adapter_id}' received unrecognized parameter(s): {sorted(unknown)}"
        )


class ToolAdapter(Protocol):
    """A typed, fixed-command adapter. No adapter accepts a raw command."""

    descriptor: AdapterDescriptor
    allowed_parameter_keys: frozenset[str]
    action_definitions: tuple[ActionDefinition, ...]

    def run(self, request: ActionRequest, *, capability_ref: str) -> AdapterResult: ...
