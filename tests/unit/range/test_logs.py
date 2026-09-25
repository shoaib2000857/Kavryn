from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from typing import Any

import pytest

from aegis.broker.adapter import ParameterValidationError
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole
from aegis.range.logs import ProxyLogsAdapter

NOW = datetime(2026, 9, 25, tzinfo=UTC)
TARGET = "service://demo-api-range"


def _request(**updates: Any) -> ActionRequest:
    fields: dict[str, Any] = {
        "id": "telemetry-request-1",
        "case_id": "AGE-0001",
        "actor_id": "control:investigator",
        "role": ActorRole.CONTROL_PLANE,
        "action_type": "telemetry.read",
        "target_ref": TARGET,
        "adapter": "range.proxy.logs",
        "parameters": {},
        "reason": "Read telemetry for an authorized synthetic range.",
        "requested_at": NOW,
    }
    fields.update(updates)
    return ActionRequest.model_validate(fields)


def test_reads_only_the_configured_container_and_bounds_log_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["argv"] = argv
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, "x" * (512 * 1024 + 64), "")

    monkeypatch.setattr("aegis.range.logs.subprocess.run", fake_run)
    adapter = ProxyLogsAdapter(container_name="aegis-proxy-AGE-0001", target_ref=TARGET)
    result = adapter.run(_request(), capability_ref="cap-test")

    assert observed["argv"] == [
        "docker",
        "logs",
        "--tail",
        "200",
        "aegis-proxy-AGE-0001",
    ]
    assert observed["kwargs"]["timeout"] == 10  # type: ignore[index]
    assert result.exit_status == "success"
    assert len(result.output["logs"].encode()) <= 512 * 1024


def test_rejects_model_selected_container_and_unknown_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        pytest.fail("invalid request must not invoke Docker")

    monkeypatch.setattr("aegis.range.logs.subprocess.run", fail_if_called)
    adapter = ProxyLogsAdapter(container_name="aegis-proxy-AGE-0001", target_ref=TARGET)
    with pytest.raises(ParameterValidationError, match="configured range"):
        adapter.run(_request(target_ref="service://other-case"), capability_ref="cap-test")
    with pytest.raises(ParameterValidationError, match="unrecognized"):
        adapter.run(_request(parameters={"container": "other"}), capability_ref="cap-test")


def test_timeout_is_a_non_success_result_with_bounded_partial_logs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timed_out(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(
            cmd=argv, timeout=kwargs["timeout"], output=b"partial telemetry"
        )

    monkeypatch.setattr("aegis.range.logs.subprocess.run", timed_out)
    adapter = ProxyLogsAdapter(container_name="aegis-proxy-AGE-0001", target_ref=TARGET)
    result = adapter.run(_request(), capability_ref="cap-test")

    assert result.exit_status == "timeout"
    assert result.output["logs"] == "partial telemetry"


def test_adapter_rejects_option_shaped_container_name() -> None:
    with pytest.raises(ValueError, match="container_name"):
        ProxyLogsAdapter(container_name="--help", target_ref=TARGET)
