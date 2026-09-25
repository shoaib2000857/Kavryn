from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult


def test_sandbox_request_defaults_to_no_network_and_requires_positive_limits() -> None:
    request = SandboxExecutionRequest(
        image="analysis@sha256:" + "a" * 64,
        command=("semgrep", "--json"),
        timeout_seconds=30,
        memory_mb=512,
        cpus=1,
    )
    assert request.network == "none"

    with pytest.raises(ValidationError):
        SandboxExecutionRequest(
            image="analysis@sha256:" + "a" * 64,
            command=("semgrep",),
            network="bridge",
            timeout_seconds=30,
            memory_mb=512,
            cpus=1,
        )


def test_sandbox_result_represents_timeout_without_claiming_success() -> None:
    result = SandboxExecutionResult(
        exit_code=None,
        stdout="partial",
        stderr="deadline exceeded",
        timed_out=True,
        duration_seconds=30,
    )
    assert result.exit_code is None
    assert result.timed_out
