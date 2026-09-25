from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from aegis.broker.adapter import (
    AdapterDescriptor,
    AdapterLimits,
    AdapterPermissions,
    ParameterValidationError,
)
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole
from aegis.domain.policy import RiskTier
from aegis.evidence.store import InMemoryArtifactStore
from aegis.tools.static_analysis import make_semgrep_adapter
from aegis.workers.container import ContainerRunResult, ContainerRunSpec, SourcePathError

VALID_SEMGREP_STDOUT = json.dumps(
    {
        "results": [
            {
                "check_id": "python.lang.security.audit.path-traversal",
                "path": "app.py",
                "start": {"line": 17},
                "extra": {"severity": "ERROR", "message": "possible path traversal"},
            }
        ]
    }
)


def _descriptor() -> AdapterDescriptor:
    return AdapterDescriptor(
        id="semgrep.scan",
        version=1,
        category="static-analysis",
        permissions=AdapterPermissions(filesystem="read-target"),
        risk_tier=RiskTier.R1_ANALYZE,
        limits=AdapterLimits(timeout_seconds=300, cpu=2, memory_mb=2048),
        parser="semgrep-json-v1",
    )


def _request(now: datetime, source_dir: str, **overrides: Any) -> ActionRequest:
    defaults: dict[str, Any] = {
        "id": "req-0001",
        "case_id": "AGE-0001",
        "actor_id": "reasoning_runtime:v1",
        "role": ActorRole.REASONING_RUNTIME,
        "action_type": "scan.run",
        "target_ref": "workspace://AGE-0001/candidate/x",
        "adapter": "semgrep.scan",
        "parameters": {"source_dir": source_dir},
        "reason": "scan the candidate workspace",
        "requested_at": now,
    }
    defaults.update(overrides)
    return ActionRequest(**defaults)


class _FakeRunner:
    def __init__(self, result: ContainerRunResult) -> None:
        self.result = result
        self.specs: list[ContainerRunSpec] = []

    def __call__(self, spec: ContainerRunSpec) -> ContainerRunResult:
        self.specs.append(spec)
        return self.result


def test_successful_scan_produces_normalized_findings_and_digest(
    tmp_path: Path, now: datetime
) -> None:
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=1,
            stdout=VALID_SEMGREP_STDOUT,
            stderr="",
            timed_out=False,
            duration_seconds=0.5,
        )
    )
    store = InMemoryArtifactStore()
    adapter = make_semgrep_adapter(
        _descriptor(),
        artifacts=store,
        allowed_source_root=str(tmp_path),
        image_ref="aegis-analysis-worker@sha256:" + "a" * 64,
        runner=fake,
    )
    result = adapter.run(_request(now, str(tmp_path)), capability_ref="capability://AGE-0001/cap-1")
    assert result.exit_status == "success"
    assert result.output["findings"][0]["rule_id"] == "python.lang.security.audit.path-traversal"
    assert result.stdout_digest is not None
    assert store.get(result.stdout_digest) == VALID_SEMGREP_STDOUT.encode()


def test_worker_absolute_paths_are_normalized_to_source_relative_paths(
    tmp_path: Path, now: datetime
) -> None:
    output = VALID_SEMGREP_STDOUT.replace('"path": "app.py"', '"path": "/src/app.py"')
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=0,
            stdout=output,
            stderr="",
            timed_out=False,
            duration_seconds=0.1,
        )
    )
    adapter = make_semgrep_adapter(
        _descriptor(),
        artifacts=InMemoryArtifactStore(),
        allowed_source_root=str(tmp_path),
        image_ref="aegis-analysis-worker@sha256:" + "a" * 64,
        runner=fake,
    )
    result = adapter.run(
        _request(now, str(tmp_path)), capability_ref="capability://AGE-0001/cap-path"
    )
    assert result.exit_status == "success"
    assert result.output["findings"][0]["file"] == "app.py"


def test_worker_finding_path_outside_mount_is_reported_as_failure(
    tmp_path: Path, now: datetime
) -> None:
    output = VALID_SEMGREP_STDOUT.replace('"path": "app.py"', '"path": "/etc/passwd"')
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=0,
            stdout=output,
            stderr="",
            timed_out=False,
            duration_seconds=0.1,
        )
    )
    adapter = make_semgrep_adapter(
        _descriptor(),
        artifacts=InMemoryArtifactStore(),
        allowed_source_root=str(tmp_path),
        image_ref="aegis-analysis-worker@sha256:" + "a" * 64,
        runner=fake,
    )
    result = adapter.run(
        _request(now, str(tmp_path)), capability_ref="capability://AGE-0001/cap-outside"
    )
    assert result.exit_status == "failure"
    assert result.output == {"parse_error": True}


def test_container_spec_uses_no_network_and_read_only_mount(tmp_path: Path, now: datetime) -> None:
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=0, stdout='{"results": []}', stderr="", timed_out=False, duration_seconds=0.1
        )
    )
    adapter = make_semgrep_adapter(
        _descriptor(),
        artifacts=InMemoryArtifactStore(),
        allowed_source_root=str(tmp_path),
        image_ref="aegis-analysis-worker@sha256:" + "a" * 64,
        runner=fake,
    )
    adapter.run(_request(now, str(tmp_path)), capability_ref="capability://AGE-0001/cap-1")
    assert len(fake.specs) == 1
    spec = fake.specs[0]
    assert spec.network == "none"
    assert len(spec.read_only_mounts) == 1
    host_path, container_path = spec.read_only_mounts[0]
    assert container_path == "/src"
    assert host_path == str(tmp_path)


def test_malformed_output_is_reported_as_failure_not_silently_empty(
    tmp_path: Path, now: datetime
) -> None:
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=2, stdout="not json", stderr="crash", timed_out=False, duration_seconds=0.1
        )
    )
    adapter = make_semgrep_adapter(
        _descriptor(),
        artifacts=InMemoryArtifactStore(),
        allowed_source_root=str(tmp_path),
        image_ref="aegis-analysis-worker@sha256:" + "a" * 64,
        runner=fake,
    )
    result = adapter.run(_request(now, str(tmp_path)), capability_ref="capability://AGE-0001/cap-1")
    assert result.exit_status == "failure"
    assert result.output.get("parse_error") is True


def test_timeout_is_recorded_as_data(tmp_path: Path, now: datetime) -> None:
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=None, stdout="", stderr="", timed_out=True, duration_seconds=300.0
        )
    )
    adapter = make_semgrep_adapter(
        _descriptor(),
        artifacts=InMemoryArtifactStore(),
        allowed_source_root=str(tmp_path),
        image_ref="aegis-analysis-worker@sha256:" + "a" * 64,
        runner=fake,
    )
    result = adapter.run(_request(now, str(tmp_path)), capability_ref="capability://AGE-0001/cap-1")
    assert result.exit_status == "timeout"


def test_unrecognized_parameter_is_rejected_before_any_container_run(
    tmp_path: Path, now: datetime
) -> None:
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=0, stdout="{}", stderr="", timed_out=False, duration_seconds=0.0
        )
    )
    adapter = make_semgrep_adapter(
        _descriptor(),
        artifacts=InMemoryArtifactStore(),
        allowed_source_root=str(tmp_path),
        image_ref="aegis-analysis-worker@sha256:" + "a" * 64,
        runner=fake,
    )
    request = _request(now, str(tmp_path), parameters={"source_dir": str(tmp_path), "extra": "bad"})
    with pytest.raises(ParameterValidationError):
        adapter.run(request, capability_ref="capability://AGE-0001/cap-1")
    assert fake.specs == []


def test_path_outside_allowed_root_is_rejected_before_any_container_run(
    tmp_path: Path, now: datetime
) -> None:
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=0, stdout="{}", stderr="", timed_out=False, duration_seconds=0.0
        )
    )
    allowed_root = tmp_path / "fixtures"
    allowed_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    adapter = make_semgrep_adapter(
        _descriptor(),
        artifacts=InMemoryArtifactStore(),
        allowed_source_root=str(allowed_root),
        image_ref="aegis-analysis-worker@sha256:" + "a" * 64,
        runner=fake,
    )
    with pytest.raises(SourcePathError):
        adapter.run(_request(now, str(outside)), capability_ref="capability://AGE-0001/cap-1")
    assert fake.specs == []
