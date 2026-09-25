from __future__ import annotations

import subprocess

import pytest

from aegis.range.docker_cmd import DockerCommandError
from aegis.range.service import ServiceSpec, container_logs, start_service, stop_service


class _FakeRunner:
    def __init__(
        self, returncode: int = 0, stdout: str = "container-id-123", stderr: str = ""
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        return subprocess.CompletedProcess(
            argv, self.returncode, stdout=self.stdout, stderr=self.stderr
        )


def _spec(**overrides: object) -> ServiceSpec:
    defaults: dict[str, object] = {
        "image": "aegis-range-app@sha256:" + "a" * 64,
        "name": "aegis-range-app-AGE-0001",
        "network": "aegis-range-AGE-0001",
    }
    defaults.update(overrides)
    return ServiceSpec(**defaults)


def test_start_service_builds_detached_run_argv_and_returns_container_id() -> None:
    fake = _FakeRunner(stdout="abc123\n")
    container_id = start_service(_spec(), runner=fake)
    assert container_id == "abc123"
    argv = fake.calls[0]
    assert argv[:3] == ["docker", "run", "-d"]
    assert "--name" in argv and "aegis-range-app-AGE-0001" in argv
    assert "--network" in argv and "aegis-range-AGE-0001" in argv


def test_start_service_never_publishes_a_port_when_unset() -> None:
    fake = _FakeRunner()
    start_service(_spec(), runner=fake)
    assert "-p" not in fake.calls[0]


def test_start_service_publishes_the_given_port() -> None:
    fake = _FakeRunner()
    start_service(_spec(published_port=(18081, 8081)), runner=fake)
    argv = fake.calls[0]
    assert "-p" in argv
    assert argv[argv.index("-p") + 1] == "18081:8081"


def test_start_service_includes_env_and_volumes() -> None:
    fake = _FakeRunner()
    start_service(
        _spec(
            env={"AEGIS_BACKEND_URL": "http://app:8080"},
            volumes=(("/host/rules", "/rules", "ro"),),
        ),
        runner=fake,
    )
    argv = fake.calls[0]
    assert "-e" in argv
    assert argv[argv.index("-e") + 1] == "AEGIS_BACKEND_URL=http://app:8080"
    assert "-v" in argv
    assert argv[argv.index("-v") + 1] == "/host/rules:/rules:ro"


def test_start_service_raises_on_failure() -> None:
    fake = _FakeRunner(returncode=1, stderr="port already allocated")
    with pytest.raises(DockerCommandError):
        start_service(_spec(), runner=fake)


def test_stop_service_uses_force_remove() -> None:
    fake = _FakeRunner()
    stop_service("aegis-range-app-AGE-0001", runner=fake)
    assert fake.calls == [["docker", "rm", "-f", "aegis-range-app-AGE-0001"]]


def test_container_logs_combines_stdout_and_stderr() -> None:
    fake = _FakeRunner(stdout="line one\n", stderr="line two\n")
    logs = container_logs("aegis-range-app-AGE-0001", runner=fake)
    assert "line one" in logs
    assert "line two" in logs
