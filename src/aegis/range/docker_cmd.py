"""A narrow, typed wrapper around long-lived ``docker`` CLI operations.

Complements ``aegis.workers.container.run_container`` (one-shot,
blocking analysis runs) with the operations a runtime range needs:
starting/stopping a detached service, reading its logs, and managing
its network. Argument arrays only, never a shell string (ADR-006) --
the same invariant as the rest of the container-backend code.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable

__all__ = ["CommandRunner", "DockerCommandError", "default_runner"]


class DockerCommandError(RuntimeError):
    """Raised when a docker CLI invocation fails or cannot be run at all."""


CommandRunner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]


def default_runner(argv: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
    except OSError as exc:
        raise DockerCommandError(f"failed to invoke docker: {exc}") from exc
