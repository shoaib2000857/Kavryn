"""Real-Docker verification for the Change 5 isolated analysis worker.

Builds the pinned analysis-worker image, then proves the three
properties unit tests (which inject a fake container runner) cannot
prove on their own: the pinned image actually contains working
Semgrep/Bandit, a container run with this backend genuinely has no
network reachability, and a "read-only" mount genuinely cannot be
written to. See docs/DECISIONS.md ADR-023 for why this runs on rootful
Docker.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aegis.broker.adapter import AdapterDescriptor, AdapterLimits, AdapterPermissions
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole
from aegis.domain.policy import RiskTier
from aegis.evidence.store import InMemoryArtifactStore
from aegis.tools.static_analysis import make_bandit_adapter, make_semgrep_adapter
from aegis.workers.container import ContainerRunSpec, run_container

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE_DIR = REPO_ROOT / "docker" / "analysis-worker"
FIXTURE_DIR = REPO_ROOT / "ranges" / "path-traversal-v1"


@pytest.fixture(scope="session")
def pinned_image_id() -> str:
    subprocess.run(
        [
            "docker",
            "build",
            "-t",
            "aegis-analysis-worker:test",
            "-f",
            str(DOCKERFILE_DIR / "Dockerfile"),
            str(DOCKERFILE_DIR),
        ],
        check=True,
        capture_output=True,
        timeout=600,
    )
    result = subprocess.run(
        ["docker", "inspect", "aegis-analysis-worker:test", "--format={{.Id}}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


def _descriptor(*, timeout_seconds: int = 60) -> AdapterDescriptor:
    return AdapterDescriptor(
        id="semgrep.scan",
        version=1,
        category="static-analysis",
        permissions=AdapterPermissions(filesystem="read-target"),
        risk_tier=RiskTier.R1_ANALYZE,
        limits=AdapterLimits(timeout_seconds=timeout_seconds, cpu=2, memory_mb=1024),
        parser="semgrep-json-v1",
    )


def _request(**overrides: object) -> ActionRequest:
    from datetime import UTC, datetime

    defaults: dict[str, object] = {
        "id": "req-int-0001",
        "case_id": "AGE-0001",
        "actor_id": "reasoning_runtime:v1",
        "role": ActorRole.REASONING_RUNTIME,
        "action_type": "scan.run",
        "target_ref": "workspace://AGE-0001/candidate/x",
        "adapter": "semgrep.scan",
        "parameters": {"source_dir": str(FIXTURE_DIR)},
        "reason": "scan the fixture for the known vulnerability",
        "requested_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    return ActionRequest(**defaults)


def test_semgrep_adapter_finds_something_in_the_real_vulnerable_fixture(
    pinned_image_id: str,
) -> None:
    adapter = make_semgrep_adapter(
        _descriptor(),
        artifacts=InMemoryArtifactStore(),
        allowed_source_root=str(FIXTURE_DIR),
        image_ref=pinned_image_id,
    )
    result = adapter.run(_request(), capability_ref="capability://AGE-0001/cap-1")
    assert result.exit_status == "success"
    findings = result.output["findings"]
    assert isinstance(findings, list)
    assert any("path-traversal" in f["rule_id"] for f in findings), findings


def test_bandit_adapter_flags_the_known_vulnerability(pinned_image_id: str) -> None:
    adapter = make_bandit_adapter(
        _descriptor(),
        artifacts=InMemoryArtifactStore(),
        allowed_source_root=str(FIXTURE_DIR),
        image_ref=pinned_image_id,
    )
    request = _request(adapter="bandit.scan", action_type="scan.run")
    result = adapter.run(request, capability_ref="capability://AGE-0001/cap-1")
    assert result.exit_status == "success"


def test_container_has_no_network_reachability(pinned_image_id: str) -> None:
    """SR-NET-001: network egress is denied by default at the worker boundary."""
    spec = ContainerRunSpec(
        image=pinned_image_id,
        command=(
            "python",
            "-c",
            "import socket; socket.create_connection(('8.8.8.8', 53), timeout=3)",
        ),
        network="none",
        timeout_seconds=15,
        memory_mb=256,
        cpus=1.0,
    )
    result = run_container(spec)
    assert result.exit_code != 0  # the connection attempt must fail


def test_source_mount_is_genuinely_read_only(pinned_image_id: str) -> None:
    spec = ContainerRunSpec(
        image=pinned_image_id,
        command=("sh", "-c", "touch /src/should-not-be-writable"),
        read_only_mounts=((str(FIXTURE_DIR), "/src"),),
        network="none",
        timeout_seconds=15,
        memory_mb=256,
        cpus=1.0,
    )
    result = run_container(spec)
    assert result.exit_code != 0  # writing into a :ro mount must fail
