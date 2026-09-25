from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

import pytest

from aegis.broker.adapter import AdapterDescriptor, AdapterResult, ParameterValidationError
from aegis.broker.mock import MockAdapter
from aegis.domain.action import ActionRequest


def test_mock_adapter_returns_default_success_result(
    scan_descriptor: AdapterDescriptor, now: datetime, make_request: Callable[..., ActionRequest]
) -> None:
    adapter = MockAdapter(scan_descriptor, allowed_parameter_keys=frozenset({"ruleset_ref"}))
    result = adapter.run(make_request(now), capability_ref="capability://AGE-0001/cap-1")
    assert result.exit_status == "success"


def test_mock_adapter_returns_configured_result(
    scan_descriptor: AdapterDescriptor, now: datetime, make_request: Callable[..., ActionRequest]
) -> None:
    configured = AdapterResult(exit_status="failure", duration_seconds=1.5)
    adapter = MockAdapter(
        scan_descriptor, allowed_parameter_keys=frozenset({"ruleset_ref"}), result=configured
    )
    result = adapter.run(make_request(now), capability_ref="capability://AGE-0001/cap-1")
    assert result == configured


def test_mock_adapter_simulates_timeout_without_raising(
    scan_descriptor: AdapterDescriptor, now: datetime, make_request: Callable[..., ActionRequest]
) -> None:
    adapter = MockAdapter(
        scan_descriptor, allowed_parameter_keys=frozenset({"ruleset_ref"}), simulate_timeout=True
    )
    result = adapter.run(make_request(now), capability_ref="capability://AGE-0001/cap-1")
    assert result.exit_status == "timeout"
    assert result.duration_seconds == scan_descriptor.limits.timeout_seconds


def test_mock_adapter_rejects_unrecognized_parameter_key(
    scan_descriptor: AdapterDescriptor, now: datetime, make_request: Callable[..., ActionRequest]
) -> None:
    """Command construction: reject unknown options
    (docs/TOOLS_AND_SANDBOXES.md)."""
    adapter = MockAdapter(scan_descriptor, allowed_parameter_keys=frozenset({"ruleset_ref"}))
    request = make_request(now, parameters={"unexpected_flag": "--dangerous"})
    with pytest.raises(ParameterValidationError):
        adapter.run(request, capability_ref="capability://AGE-0001/cap-1")


def test_mock_adapter_never_shells_out_string_parameters_are_inert_data(
    scan_descriptor: AdapterDescriptor, now: datetime, make_request: Callable[..., ActionRequest]
) -> None:
    """A shell-metacharacter-laden parameter value is stored and passed
    through as an ordinary string; nothing in this adapter ever
    concatenates it into a command, so there is no injection surface."""
    adapter = MockAdapter(scan_descriptor, allowed_parameter_keys=frozenset({"ruleset_ref"}))
    request = make_request(now, parameters={"ruleset_ref": "rules; rm -rf / #"})
    result = adapter.run(request, capability_ref="capability://AGE-0001/cap-1")
    assert result.exit_status == "success"
    assert adapter.calls[0].parameters["ruleset_ref"] == "rules; rm -rf / #"


def test_mock_adapter_records_every_call(
    scan_descriptor: AdapterDescriptor, now: datetime, make_request: Callable[..., ActionRequest]
) -> None:
    adapter = MockAdapter(scan_descriptor, allowed_parameter_keys=frozenset({"ruleset_ref"}))
    request = make_request(now)
    adapter.run(request, capability_ref="capability://AGE-0001/cap-1")
    assert adapter.calls == [request]
