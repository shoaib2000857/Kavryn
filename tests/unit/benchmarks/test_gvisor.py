from datetime import datetime
from pathlib import Path

import pytest

from aegis.benchmarks.gvisor import EvaluationPlan, GVisorEvaluationAdapter
from aegis.broker.adapter import ParameterValidationError
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole
from aegis.evidence.store import sha256_digest


def make_adapter(tmp_path: Path) -> tuple[GVisorEvaluationAdapter, EvaluationPlan]:
    root = tmp_path / "rootfs"
    scripts = root / "aegis-eval"
    scripts.mkdir(parents=True)
    source = b"echo bounded\n"
    (scripts / "model.sh").write_bytes(source)
    runsc = tmp_path / "runsc"
    runsc.touch()
    state = tmp_path / "state"
    state.mkdir()
    plan = EvaluationPlan(root, "model", sha256_digest(source).digest, "workspace://AGE-0001/test")
    return GVisorEvaluationAdapter(runsc=runsc, state_root=state, plans={"model": plan}), plan


def test_fixed_command_declares_no_network_overlay_and_all_resource_limits(tmp_path: Path) -> None:
    adapter, plan = make_adapter(tmp_path)
    command = adapter.command(plan, "aegis-eval-unit")
    for required in (
        "--rootless",
        "--network=none",
        "--force-overlay=true",
        "--property=MemoryMax=3072M",
        "--property=TasksMax=256",
        "--property=CPUQuota=200%",
        "--property=RuntimeMaxSec=300",
        "-i",
    ):
        assert required in command
    assert command[-2:] == ["/bin/bash", "/aegis-eval/model.sh"]
    assert not any("docker.sock" in value for value in command)


def test_tampered_script_and_symlink_are_rejected(tmp_path: Path) -> None:
    _adapter, plan = make_adapter(tmp_path)
    path = plan.rootfs / "aegis-eval/model.sh"
    path.write_text("echo changed\n")
    with pytest.raises(ParameterValidationError, match="digest"):
        plan.validate()
    path.unlink()
    path.symlink_to(tmp_path / "outside")
    with pytest.raises(ParameterValidationError, match="missing or escapes"):
        plan.validate()


@pytest.mark.parametrize(
    ("parameters", "target", "capability"),
    [
        ({"plan_id": "model", "host_path": "/etc"}, "workspace://AGE-0001/test", "cap"),
        ({"plan_id": "unknown"}, "workspace://AGE-0001/test", "cap"),
        ({"plan_id": "model"}, "workspace://AGE-OTHER/test", "cap"),
        ({"plan_id": "model"}, "workspace://AGE-0001/test", ""),
    ],
)
def test_untrusted_parameters_target_and_missing_capability_fail_before_execution(
    tmp_path: Path, now: datetime, parameters: dict[str, str], target: str, capability: str
) -> None:
    adapter, _plan = make_adapter(tmp_path)
    request = ActionRequest(
        id="req-gvisor-test",
        case_id="AGE-0001",
        actor_id="reasoning_runtime:test",
        role=ActorRole.REASONING_RUNTIME,
        action_type="test.run",
        target_ref=target,
        adapter="benchmark.gvisor",
        parameters=parameters,
        reason="test fixed evaluator boundary",
        requested_at=now,
    )
    with pytest.raises(ParameterValidationError):
        adapter.run(request, capability_ref=capability)
