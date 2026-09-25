"""Isolated Docker networks for one case's runtime range.

Every range gets its own Docker-internal network, joined only by that
case's app and proxy containers. The trusted host sends test traffic to
the proxy's internal address; no range container port is published.
"""

from __future__ import annotations

import re

from aegis.range.docker_cmd import CommandRunner, DockerCommandError, default_runner

__all__ = ["create_network", "remove_network"]

_NETWORK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\Z")


def _validate_network_name(name: str) -> None:
    if _NETWORK_NAME.fullmatch(name) is None:
        raise DockerCommandError("range network name is not a safe Docker identifier")


def create_network(name: str, *, runner: CommandRunner = default_runner) -> None:
    _validate_network_name(name)
    result = runner(["docker", "network", "create", "--internal", name])
    if result.returncode != 0 and "already exists" not in result.stderr:
        raise DockerCommandError(f"failed to create network '{name}': {result.stderr}")

    # A stale/pre-existing network must not silently weaken the range's
    # egress boundary. Verify the daemon's effective configuration each time.
    inspected = runner(["docker", "network", "inspect", "--format={{.Internal}}", name])
    if inspected.returncode != 0 or inspected.stdout.strip().lower() != "true":
        raise DockerCommandError(
            f"range network '{name}' is unavailable or not internally isolated"
        )


def remove_network(name: str, *, runner: CommandRunner = default_runner) -> None:
    """Best-effort teardown: a missing or in-use network is not an error here."""
    _validate_network_name(name)
    runner(["docker", "network", "rm", name])
