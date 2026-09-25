"""Isolated Docker networks for one case's runtime range.

Every range gets its own network, joined only by that case's app and
proxy containers -- no service is reachable from outside except through
the proxy's one published port (docs/TOOLS_AND_SANDBOXES.md's dynamic-
validation worker: "isolated network containing only the target
fixture").
"""

from __future__ import annotations

from aegis.range.docker_cmd import CommandRunner, DockerCommandError, default_runner

__all__ = ["create_network", "remove_network"]


def create_network(name: str, *, runner: CommandRunner = default_runner) -> None:
    result = runner(["docker", "network", "create", name])
    if result.returncode != 0 and "already exists" not in result.stderr:
        raise DockerCommandError(f"failed to create network '{name}': {result.stderr}")


def remove_network(name: str, *, runner: CommandRunner = default_runner) -> None:
    """Best-effort teardown: a missing or in-use network is not an error here."""
    runner(["docker", "network", "rm", name])
