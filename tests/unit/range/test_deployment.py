from __future__ import annotations

import hashlib
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.broker.adapter import ParameterValidationError
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole, Digest
from aegis.range.deployment import RangeDeploymentAdapter
from aegis.range.service import ServiceSpec


@pytest.fixture
def adapter(tmp_path: Path) -> RangeDeploymentAdapter:
    fixture = tmp_path / "fixture"
    (fixture / "src").mkdir(parents=True)
    (fixture / "Dockerfile").write_text("FROM scratch\n")
    (fixture / "requirements.txt").write_text("")
    (fixture / "src" / "app.py").write_text("print('safe')\n")
    image = "sha256:" + "a" * 64

    def unexpected_docker_call(argv: list[str]) -> subprocess.CompletedProcess[str]:
        raise AssertionError(f"unexpected command reached runner: {argv!r}")

    return RangeDeploymentAdapter(
        fixture_dir=str(fixture),
        source_subdirectory="src",
        allowed_files=frozenset({"app.py"}),
        base_source_digest=Digest(digest="b" * 64),
        base_image=image,
        service=ServiceSpec(image=image, name="aegis-unit-range-app", network="aegis-unit-net"),
        target_ref="service://unit-range",
        rules_file=str(tmp_path / "rules.json"),
        readiness_probe=lambda: True,
        runner=unexpected_docker_call,
    )


def _request(adapter: RangeDeploymentAdapter, **overrides: object) -> ActionRequest:
    now = datetime.now(UTC)
    defaults: dict[str, object] = {
        "id": "deploy-unit-1",
        "case_id": "AGE-UNIT-1",
        "actor_id": "control:transaction-coordinator",
        "role": ActorRole.CONTROL_PLANE,
        "action_type": "deployment.rollout",
        "target_ref": "service://unit-range",
        "adapter": adapter.descriptor.id,
        "parameters": {
            "operation": "apply",
            "candidate_diff": (
                "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-print('safe')\n+print('patched')\n"
            ),
            "diff_digest": "0" * 64,
            "base_source_digest": "b" * 64,
        },
        "reason": "test a deployment boundary",
        "requested_at": now,
    }
    defaults.update(overrides)
    return ActionRequest(**defaults)


def test_deployment_adapter_declares_narrow_docker_authority(
    adapter: RangeDeploymentAdapter,
) -> None:
    assert adapter.descriptor.permissions.docker_control == "authorized-range"
    assert adapter.descriptor.permissions.network == "none"
    assert adapter.descriptor.permissions.secrets == "none"


def test_deployment_adapter_rejects_wrong_target_before_any_docker_call(
    adapter: RangeDeploymentAdapter,
) -> None:
    with pytest.raises(ParameterValidationError, match="not bound to this configured range"):
        adapter.run(
            _request(adapter, target_ref="service://other-range"), capability_ref="cap-test"
        )


def test_deployment_adapter_rejects_tampered_diff_digest_before_any_docker_call(
    adapter: RangeDeploymentAdapter,
) -> None:
    with pytest.raises(ParameterValidationError, match="diff digest mismatch"):
        adapter.run(_request(adapter), capability_ref="cap-test")


def test_deployment_adapter_rejects_out_of_scope_diff_before_any_docker_call(
    adapter: RangeDeploymentAdapter,
) -> None:
    diff = "--- a/other.py\n+++ b/other.py\n@@ -1 +1 @@\n-a\n+b\n"
    request = _request(
        adapter,
        parameters={
            "operation": "apply",
            "candidate_diff": diff,
            "diff_digest": hashlib.sha256(diff.encode()).hexdigest(),
            "base_source_digest": "b" * 64,
        },
    )
    with pytest.raises(ParameterValidationError, match="outside the allowed set"):
        adapter.run(request, capability_ref="cap-test")
