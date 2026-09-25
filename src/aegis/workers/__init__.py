"""Execution backends (docs/IMPLEMENTATION_HANDOFF.md Change 5).

``container.py`` is the only module that invokes the ``docker`` CLI; it
is only ever called from a registered ``ToolAdapter`` running inside
the broker/worker trust boundary, never from the reasoning runtime.
"""

from aegis.workers.container import (
    ContainerRunError,
    ContainerRunResult,
    ContainerRunSpec,
    SourcePathError,
    resolve_read_only_source,
    run_container,
)

__all__ = [
    "ContainerRunError",
    "ContainerRunResult",
    "ContainerRunSpec",
    "SourcePathError",
    "resolve_read_only_source",
    "run_container",
]
