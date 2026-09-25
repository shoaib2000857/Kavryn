"""Domain-neutral contract for bounded, isolated command execution.

The core describes an execution request and result without depending on
Docker or cyber-defender code. Concrete backends own command construction and
must enforce the request's network, mount, time, and resource constraints.
"""

from __future__ import annotations

from typing import Final, Literal, Protocol

from pydantic import Field

from aegis.domain.base import AegisModel

__all__ = ["SandboxBackend", "SandboxExecutionRequest", "SandboxExecutionResult"]

SANDBOX_REQUEST_SCHEMA_VERSION: Final[Literal["aegis.sandbox_request/v1"]] = (
    "aegis.sandbox_request/v1"
)
SANDBOX_RESULT_SCHEMA_VERSION: Final[Literal["aegis.sandbox_result/v1"]] = "aegis.sandbox_result/v1"


class SandboxExecutionRequest(AegisModel):
    """Immutable description of one bounded sandbox execution."""

    schema_version: Literal["aegis.sandbox_request/v1"] = SANDBOX_REQUEST_SCHEMA_VERSION
    image: str = Field(min_length=1)
    command: tuple[str, ...] = Field(min_length=1)
    read_only_mounts: tuple[tuple[str, str], ...] = ()
    network: Literal["none"] = "none"
    timeout_seconds: int = Field(gt=0)
    memory_mb: int = Field(gt=0)
    cpus: float = Field(gt=0)
    user: str | None = None


class SandboxExecutionResult(AegisModel):
    """Observed process result; timeout and process failure remain data."""

    schema_version: Literal["aegis.sandbox_result/v1"] = SANDBOX_RESULT_SCHEMA_VERSION
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float


class SandboxBackend(Protocol):
    """Execution backend contract; implementations must fail closed."""

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Run the request while honoring every declared restriction."""
