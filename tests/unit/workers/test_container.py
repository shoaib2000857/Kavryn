from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from aegis.core.sandbox import SandboxExecutionResult
from aegis.workers.container import (
    ContainerRunError,
    ContainerRunSpec,
    SourcePathError,
    resolve_read_only_source,
    run_container,
)


def test_resolves_the_allowed_root_itself(tmp_path: Path) -> None:
    resolved = resolve_read_only_source(str(tmp_path), allowed_root=str(tmp_path))
    assert resolved == os.path.realpath(tmp_path)


def test_resolves_a_path_beneath_the_allowed_root(tmp_path: Path) -> None:
    child = tmp_path / "source"
    child.mkdir()
    resolved = resolve_read_only_source(str(child), allowed_root=str(tmp_path))
    assert resolved == os.path.realpath(child)


def test_rejects_a_path_outside_the_allowed_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-sibling"
    with pytest.raises(SourcePathError):
        resolve_read_only_source(str(outside), allowed_root=str(tmp_path))


def test_rejects_traversal_through_the_allowed_root(tmp_path: Path) -> None:
    traversal = str(tmp_path) + "/../etc"
    with pytest.raises(SourcePathError):
        resolve_read_only_source(traversal, allowed_root=str(tmp_path))


def test_rejects_symlink_escape(tmp_path: Path) -> None:
    """A symlink inside the allowed root pointing outside it must not
    be trusted as if it were really inside the root."""
    real_root = tmp_path / "root"
    real_root.mkdir()
    outside_target = tmp_path / "secret"
    outside_target.mkdir()
    escape_link = real_root / "escape"
    escape_link.symlink_to(outside_target)
    with pytest.raises(SourcePathError):
        resolve_read_only_source(str(escape_link), allowed_root=str(real_root))


def test_rejects_sibling_directory_sharing_a_string_prefix(tmp_path: Path) -> None:
    root = tmp_path / "candidate"
    root.mkdir()
    sibling = tmp_path / "candidate-evil"
    sibling.mkdir()
    with pytest.raises(SourcePathError):
        resolve_read_only_source(str(sibling), allowed_root=str(root))


def _spec(**overrides: Any) -> ContainerRunSpec:
    defaults: dict[str, Any] = {
        "image": "aegis-analysis-worker@sha256:" + "a" * 64,
        "command": ("semgrep", "--json", "/src"),
        "read_only_mounts": (("/host/source", "/src"),),
        "timeout_seconds": 60,
        "memory_mb": 512,
        "cpus": 1.0,
    }
    defaults.update(overrides)
    return ContainerRunSpec(**defaults)


def test_run_container_builds_argv_with_no_network_and_read_only_mount(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr("aegis.workers.container.subprocess.run", fake_run)
    run_container(_spec())

    argv = captured["argv"]
    assert argv[0:2] == ["docker", "run"]
    assert "--network" in argv and argv[argv.index("--network") + 1] == "none"
    assert "-v" in argv
    mount_arg = argv[argv.index("-v") + 1]
    assert mount_arg == "/host/source:/src:ro"
    # The image comes immediately before the command argv, in order.
    assert argv[-4] == _spec().image
    assert argv[-3:] == ["semgrep", "--json", "/src"]


def test_run_container_reports_timeout_as_data_not_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr("aegis.workers.container.subprocess.run", fake_run)
    result = run_container(_spec(timeout_seconds=1))
    assert result.timed_out is True
    assert result.exit_code is None


def test_run_container_raises_container_run_error_when_docker_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("docker: command not found")

    monkeypatch.setattr("aegis.workers.container.subprocess.run", fake_run)
    with pytest.raises(ContainerRunError):
        run_container(_spec())


def test_run_container_returns_stdout_and_exit_code_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, returncode=0, stdout='{"results": []}', stderr="")

    monkeypatch.setattr("aegis.workers.container.subprocess.run", fake_run)
    result = run_container(_spec())
    assert result.exit_code == 0
    assert result.stdout == '{"results": []}'
    assert result.timed_out is False


def test_run_container_accepts_an_alternate_core_backend() -> None:
    class FakeBackend:
        def __init__(self) -> None:
            self.request: ContainerRunSpec | None = None

        def execute(self, request: ContainerRunSpec) -> SandboxExecutionResult:
            self.request = request
            return SandboxExecutionResult(
                exit_code=0,
                stdout="isolated",
                stderr="",
                timed_out=False,
                duration_seconds=0.01,
            )

    backend = FakeBackend()
    result = run_container(_spec(), backend=backend)
    assert backend.request == _spec()
    assert result.stdout == "isolated"
