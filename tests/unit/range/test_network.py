from __future__ import annotations

import subprocess

import pytest

from aegis.range.docker_cmd import DockerCommandError
from aegis.range.network import create_network, remove_network


class _FakeRunner:
    def __init__(self, returncode: int = 0, stderr: str = "") -> None:
        self.returncode = returncode
        self.stderr = stderr
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, self.returncode, stdout="", stderr=self.stderr)


def test_create_network_builds_expected_argv() -> None:
    fake = _FakeRunner()
    create_network("aegis-range-AGE-0001", runner=fake)
    assert fake.calls == [["docker", "network", "create", "aegis-range-AGE-0001"]]


def test_create_network_raises_on_failure() -> None:
    fake = _FakeRunner(returncode=1, stderr="some docker error")
    with pytest.raises(DockerCommandError):
        create_network("aegis-range-AGE-0001", runner=fake)


def test_create_network_tolerates_already_exists() -> None:
    fake = _FakeRunner(returncode=1, stderr="Error: network already exists")
    create_network("aegis-range-AGE-0001", runner=fake)  # must not raise


def test_remove_network_is_best_effort() -> None:
    fake = _FakeRunner(returncode=1, stderr="no such network")
    remove_network("aegis-range-AGE-0001", runner=fake)  # must not raise
    assert fake.calls == [["docker", "network", "rm", "aegis-range-AGE-0001"]]
