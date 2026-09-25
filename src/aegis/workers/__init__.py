"""Analysis-worker sandbox backend (docs/IMPLEMENTATION_HANDOFF.md Change 5).

The default implementation uses the core ``SandboxBackend`` contract and
rootful Docker. It is called by registered tool adapters, never directly by
the reasoning runtime.
"""

from aegis.workers.container import (
    ContainerRunError,
    ContainerRunResult,
    ContainerRunSpec,
    DockerSandboxBackend,
    SourcePathError,
    resolve_read_only_source,
    run_container,
)

__all__ = [
    "ContainerRunError",
    "ContainerRunResult",
    "ContainerRunSpec",
    "DockerSandboxBackend",
    "SourcePathError",
    "resolve_read_only_source",
    "run_container",
]
