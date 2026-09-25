from __future__ import annotations

import shutil
import subprocess

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


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _docker_available():
        return
    skip_no_docker = pytest.mark.skip(reason="Docker is not available in this environment")
    for item in items:
        item.add_marker(skip_no_docker)
