"""A Docker implementation of the core sandbox execution contract.

See docs/TOOLS_AND_SANDBOXES.md "Worker classes: Read-only analysis
worker" (read-only source mount, no network, strict resource/time
limits) and "Command construction" (argument arrays, never shell
concatenation). This backend is only called from the registered analysis
tool adapter, never from the reasoning runtime or the model. Range-specific
Docker lifecycle operations remain in ``aegis.range`` and are separately
typed and scope-bound.

docs/DECISIONS.md ADR-023: this runs against the host's Docker daemon,
which is rootful in the current implementation environment (no
rootless mode available) — an owner-accepted interim exception to
ADR-012, scoped to local low-risk static-analysis fixtures.
"""

from __future__ import annotations

import os
import subprocess
import time

from aegis.core.sandbox import (
    SandboxBackend,
    SandboxExecutionRequest,
    SandboxExecutionResult,
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


ContainerRunSpec = SandboxExecutionRequest
ContainerRunResult = SandboxExecutionResult


def _build_argv(spec: SandboxExecutionRequest) -> list[str]:
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


class DockerSandboxBackend:
    """Run bounded one-shot jobs through the host Docker CLI.

    Docker is still rootful in the current environment. This implementation
    is a backend, not proof that Docker is a hardened boundary for hostile
    code; callers must use only the approved fixture classes documented by
    the threat model.
    """

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        argv = _build_argv(request)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=request.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxExecutionResult(
                exit_code=None,
                stdout=exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr=exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
                timed_out=True,
                duration_seconds=time.monotonic() - started,
            )
        except OSError as exc:
            raise ContainerRunError(f"failed to invoke docker: {exc}") from exc
        return SandboxExecutionResult(
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
            duration_seconds=time.monotonic() - started,
        )


def run_container(
    spec: SandboxExecutionRequest,
    *,
    backend: SandboxBackend | None = None,
) -> SandboxExecutionResult:
    """Run ``spec`` through the selected backend and return its typed result.

    A timeout is reported as data (``timed_out=True``), not raised as an
    exception — mirroring ``AdapterResult``'s "a completed tool call
    does not imply a successful outcome" philosophy so callers have one
    uniform way to inspect what happened. Only a failure to invoke
    ``docker`` at all (e.g. the binary is missing) raises
    ``ContainerRunError`` for the default Docker backend.
    """
    return (backend or DockerSandboxBackend()).execute(spec)
