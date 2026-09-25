"""Starting, stopping, and reading logs from a detached range container.

Neither the app nor the containment proxy is given a published port in
the current internal-network range. The trusted host reaches the proxy
through its internal container address. ``ServiceSpec`` retains an
optional port-mapping field for future explicitly reviewed scenarios.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import PurePosixPath

from pydantic import Field, ValidationInfo, field_validator

from aegis.domain.base import AegisModel
from aegis.range.docker_cmd import CommandRunner, DockerCommandError, default_runner

__all__ = ["ServiceSpec", "container_ip", "container_logs", "start_service", "stop_service"]

_CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\Z")
_IMAGE_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}\Z")
_ENVIRONMENT_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class ServiceSpec(AegisModel):
    image: str = Field(min_length=1)
    name: str = Field(min_length=1)
    network: str = Field(min_length=1)
    env: dict[str, str] = Field(default_factory=dict)
    published_port: tuple[int, int] | None = None  # (host_port, container_port)
    volumes: tuple[tuple[str, str, str], ...] = ()  # (host_path, container_path, mode)

    @staticmethod
    def _safe_identifier(value: str, *, field_name: str) -> str:
        if _CONTAINER_NAME.fullmatch(value) is None:
            raise ValueError(f"{field_name} must be a safe Docker identifier")
        return value

    @staticmethod
    def _safe_image_reference(value: str) -> str:
        if _IMAGE_REFERENCE.fullmatch(value) is None:
            raise ValueError("image must be a simple, non-option Docker image reference")
        return value

    @staticmethod
    def _validate_volume(volume: tuple[str, str, str]) -> tuple[str, str, str]:
        host_path, container_path, mode = volume
        host = PurePosixPath(host_path)
        target = PurePosixPath(container_path)
        if (
            not host.is_absolute()
            or ".." in host.parts
            or ":" in host_path
            or not target.is_absolute()
            or ".." in target.parts
            or target.as_posix() != container_path
        ):
            raise ValueError("volume paths must be absolute, normalized, and traversal-free")
        if mode != "ro":
            raise ValueError("range service host mounts must be read-only")
        return volume

    @staticmethod
    def _validate_port_pair(value: tuple[int, int] | None) -> tuple[int, int] | None:
        if value is not None and any(not 1 <= port <= 65535 for port in value):
            raise ValueError("published ports must be in the range 1..65535")
        return value

    @staticmethod
    def _validate_environment(value: dict[str, str]) -> dict[str, str]:
        if any(
            _ENVIRONMENT_KEY.fullmatch(key) is None or "\x00" in content
            for key, content in value.items()
        ):
            raise ValueError("environment must use valid keys and NUL-free values")
        return value

    # Keep validation in Pydantic so every caller, including future API or
    # benchmark adapters, receives the same fail-closed checks.
    @field_validator("image")
    @classmethod
    def validate_image(cls, value: str) -> str:
        return cls._safe_image_reference(value)

    @field_validator("name", "network")
    @classmethod
    def validate_identifiers(cls, value: str, info: ValidationInfo) -> str:
        field_name = info.field_name or "identifier"
        return cls._safe_identifier(value, field_name=field_name)

    @field_validator("volumes")
    @classmethod
    def validate_volumes(
        cls, value: tuple[tuple[str, str, str], ...]
    ) -> tuple[tuple[str, str, str], ...]:
        return tuple(cls._validate_volume(volume) for volume in value)

    @field_validator("published_port")
    @classmethod
    def validate_published_port(cls, value: tuple[int, int] | None) -> tuple[int, int] | None:
        return cls._validate_port_pair(value)

    @field_validator("env")
    @classmethod
    def validate_env(cls, value: dict[str, str]) -> dict[str, str]:
        return cls._validate_environment(value)


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
    if _CONTAINER_NAME.fullmatch(name) is None:
        raise DockerCommandError("container name is not a safe Docker identifier")
    runner(["docker", "rm", "-f", name])


def container_logs(name: str, *, runner: CommandRunner = default_runner) -> str:
    if _CONTAINER_NAME.fullmatch(name) is None:
        raise DockerCommandError("container name is not a safe Docker identifier")
    result = runner(["docker", "logs", name])
    return result.stdout + result.stderr


def container_ip(name: str, *, runner: CommandRunner = default_runner) -> str:
    """Resolve a fixed range container address for trusted host-side probes.

    Internal Docker networks are reachable from the trusted host while
    preventing container egress; this avoids publishing the range proxy port.
    """
    if _CONTAINER_NAME.fullmatch(name) is None:
        raise DockerCommandError("container name is not a safe Docker identifier")
    result = runner(
        [
            "docker",
            "inspect",
            "--format={{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            name,
        ]
    )
    if result.returncode != 0:
        raise DockerCommandError(f"failed to inspect range container '{name}'")
    try:
        return str(ipaddress.ip_address(result.stdout.strip()))
    except ValueError as exc:
        raise DockerCommandError("range container has no valid IPv4/IPv6 address") from exc
