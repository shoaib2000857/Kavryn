from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=10, check=True)
    except (subprocess.SubprocessError, OSError):
        return False
    return True


@pytest.fixture(scope="session")
def docker_available() -> bool:
    return _docker_available()


@pytest.fixture(scope="session")
def analysis_worker_image_id() -> str:
    repository_root = Path(__file__).resolve().parents[2]
    dockerfile_dir = repository_root / "docker" / "analysis-worker"
    subprocess.run(
        [
            "docker",
            "build",
            "-t",
            "aegis-analysis-worker:integration",
            "-f",
            str(dockerfile_dir / "Dockerfile"),
            str(dockerfile_dir),
        ],
        check=True,
        capture_output=True,
        timeout=600,
    )
    result = subprocess.run(
        ["docker", "inspect", "aegis-analysis-worker:integration", "--format={{.Id}}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _docker_available():
        return
    skip_no_docker = pytest.mark.skip(reason="Docker is not available in this environment")
    for item in items:
        item.add_marker(skip_no_docker)
