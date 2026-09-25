"""A narrow, typed wrapper around ``docker run`` for the analysis worker.

See docs/TOOLS_AND_SANDBOXES.md "Worker classes: Read-only analysis
worker" (read-only source mount, no network, strict resource/time
limits) and "Command construction" (argument arrays, never shell
concatenation). This is the only place in the codebase that invokes the
``docker`` CLI; it is never reachable from the reasoning runtime or the
model — only from a registered ``ToolAdapter`` implementation running
inside the trusted broker/worker boundary.

docs/DECISIONS.md ADR-023: this runs against the host's Docker daemon,
which is rootful in the current implementation environment (no
rootless mode available) — an owner-accepted interim exception to
ADR-012, scoped to local low-risk static-analysis fixtures.
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Literal

from pydantic import Field

from aegis.domain.base import AegisModel

__all__ = [
    "ContainerRunError",
    "ContainerRunResult",
    "ContainerRunSpec",
    "SourcePathError",
    "resolve_read_only_source",
    "run_container",
]


class ContainerRunError(RuntimeError):
    """Raised when the ``docker`` CLI itself cannot be invoked at all."""


class SourcePathError(ValueError):
    """Raised when a requested source path is not safely mountable."""


def resolve_read_only_source(path: str, *, allowed_root: str) -> str:
    """Canonicalize ``path`` and require it to be ``allowed_root`` or beneath it.

    Mirrors ``aegis.policy.targets``'s ``.``/``..`` and shared-string-
    prefix pitfalls, but at the host-filesystem layer: this runs right
    before a path is bind-mounted into a container, so it must resolve
    symlinks and ``..`` itself rather than trust the caller's string.
    """
    real_root = os.path.realpath(allowed_root)
    real_path = os.path.realpath(path)
    if real_path != real_root and not real_path.startswith(real_root + os.sep):
        raise SourcePathError(f"'{path}' resolves outside the allowed root '{allowed_root}'")
    return real_path


class ContainerRunSpec(AegisModel):
    """A fully-resolved, typed specification for one container run.

    ``command`` is always an argument list, never a shell string — there
    is no field here that could carry shell metacharacters into a
    concatenated command line (ADR-006, docs/THREAT_MODEL.md T02).
    """

    image: str = Field(min_length=1)
    command: tuple[str, ...] = Field(min_length=1)
    read_only_mounts: tuple[tuple[str, str], ...] = ()
    network: Literal["none"] = "none"
    timeout_seconds: int = Field(gt=0)
    memory_mb: int = Field(gt=0)
    cpus: float = Field(gt=0)
    user: str | None = None


class ContainerRunResult(AegisModel):
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float


def _build_argv(spec: ContainerRunSpec) -> list[str]:
    argv = [
        "docker",
        "run",
        "--rm",
        "--network",
        spec.network,
        "--memory",
        f"{spec.memory_mb}m",
        "--cpus",
        str(spec.cpus),
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
    ]
    if spec.user is not None:
        argv += ["--user", spec.user]
    for host_path, container_path in spec.read_only_mounts:
        argv += ["-v", f"{host_path}:{container_path}:ro"]
    argv.append(spec.image)
    argv.extend(spec.command)
    return argv


def run_container(spec: ContainerRunSpec) -> ContainerRunResult:
    """Run ``spec`` via ``docker run`` and return its typed result.

    A timeout is reported as data (``timed_out=True``), not raised as an
    exception — mirroring ``AdapterResult``'s "a completed tool call
    does not imply a successful outcome" philosophy so callers have one
    uniform way to inspect what happened. Only a failure to invoke
    ``docker`` at all (e.g. the binary is missing) raises
    ``ContainerRunError``.
    """
    argv = _build_argv(spec)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=spec.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return ContainerRunResult(
            exit_code=None,
            stdout=exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            stderr=exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
            timed_out=True,
            duration_seconds=time.monotonic() - started,
        )
    except OSError as exc:
        raise ContainerRunError(f"failed to invoke docker: {exc}") from exc
    return ContainerRunResult(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        timed_out=False,
        duration_seconds=time.monotonic() - started,
    )
