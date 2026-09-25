"""Starting, stopping, and reading logs from a detached range container.

The app container in a range is never given a published port; only the
containment proxy is (docs/DECISIONS.md ADR-029) -- ``ServiceSpec`` can
express both by leaving ``published_port`` unset for the app.
"""

from __future__ import annotations

from pydantic import Field

from aegis.domain.base import AegisModel
from aegis.range.docker_cmd import CommandRunner, DockerCommandError, default_runner

__all__ = ["ServiceSpec", "container_logs", "start_service", "stop_service"]


class ServiceSpec(AegisModel):
    image: str = Field(min_length=1)
    name: str = Field(min_length=1)
    network: str = Field(min_length=1)
    env: dict[str, str] = Field(default_factory=dict)
    published_port: tuple[int, int] | None = None  # (host_port, container_port)
    volumes: tuple[tuple[str, str, str], ...] = ()  # (host_path, container_path, mode)


def _build_run_argv(spec: ServiceSpec) -> list[str]:
    argv = ["docker", "run", "-d", "--name", spec.name, "--network", spec.network]
    for key, value in spec.env.items():
        argv += ["-e", f"{key}={value}"]
    if spec.published_port is not None:
        host_port, container_port = spec.published_port
        argv += ["-p", f"{host_port}:{container_port}"]
    for host_path, container_path, mode in spec.volumes:
        argv += ["-v", f"{host_path}:{container_path}:{mode}"]
    argv.append(spec.image)
    return argv


def start_service(spec: ServiceSpec, *, runner: CommandRunner = default_runner) -> str:
    """Start a detached container from ``spec`` and return its container id."""
    result = runner(_build_run_argv(spec))
    if result.returncode != 0:
        raise DockerCommandError(f"failed to start service '{spec.name}': {result.stderr}")
    return result.stdout.strip()


def stop_service(name: str, *, runner: CommandRunner = default_runner) -> None:
    """Best-effort teardown: stop and remove a container by name."""
    runner(["docker", "rm", "-f", name])


def container_logs(name: str, *, runner: CommandRunner = default_runner) -> str:
    result = runner(["docker", "logs", name])
    return result.stdout + result.stderr
