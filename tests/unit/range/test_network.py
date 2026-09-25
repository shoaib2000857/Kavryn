from __future__ import annotations

import subprocess

import pytest

from aegis.range.docker_cmd import DockerCommandError
from aegis.range.network import create_network, remove_network


class _FakeRunner:
    def __init__(self, *results: subprocess.CompletedProcess[str]) -> None:
        self.results = list(results)
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        if self.results:
            configured = self.results.pop(0)
            return subprocess.CompletedProcess(
                argv,
                configured.returncode,
                stdout=configured.stdout,
                stderr=configured.stderr,
            )
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


def _result(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


def test_create_network_builds_expected_argv() -> None:
    fake = _FakeRunner(_result(), _result(stdout="true\n"))
    create_network("aegis-range-AGE-0001", runner=fake)
    assert fake.calls == [
        ["docker", "network", "create", "--internal", "aegis-range-AGE-0001"],
        ["docker", "network", "inspect", "--format={{.Internal}}", "aegis-range-AGE-0001"],
    ]


def test_create_network_raises_on_failure() -> None:
    fake = _FakeRunner(_result(returncode=1, stderr="some docker error"))
    with pytest.raises(DockerCommandError):
        create_network("aegis-range-AGE-0001", runner=fake)


def test_create_network_tolerates_already_exists() -> None:
    fake = _FakeRunner(
        _result(returncode=1, stderr="Error: network already exists"),
        _result(stdout="true\n"),
    )
    create_network("aegis-range-AGE-0001", runner=fake)  # must not raise


@pytest.mark.parametrize(
    "inspect_result",
    [_result(stdout="false\n"), _result(returncode=1, stderr="network missing")],
)
def test_create_network_fails_closed_if_network_is_not_confirmed_internal(
    inspect_result: subprocess.CompletedProcess[str],
) -> None:
    fake = _FakeRunner(
        _result(returncode=1, stderr="Error: network already exists"), inspect_result
    )
    with pytest.raises(DockerCommandError, match="not internally isolated"):
        create_network("aegis-range-AGE-0001", runner=fake)


@pytest.mark.parametrize("name", ["--help", "bad name", "../escape", "", "a" * 64])
def test_network_name_rejects_option_and_path_injection(name: str) -> None:
    fake = _FakeRunner()
    with pytest.raises(DockerCommandError, match="safe Docker identifier"):
        create_network(name, runner=fake)
    assert fake.calls == []


def test_remove_network_is_best_effort() -> None:
    fake = _FakeRunner(_result(returncode=1, stderr="no such network"))
    remove_network("aegis-range-AGE-0001", runner=fake)  # must not raise
    assert fake.calls == [["docker", "network", "rm", "aegis-range-AGE-0001"]]
