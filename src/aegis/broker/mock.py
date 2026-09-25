"""``MockAdapter``: an in-process local mock worker.

See docs/IMPLEMENTATION_HANDOFF.md Change 4 ("local mock worker") and
docs/TOOLS_AND_SANDBOXES.md's isolation-maturity table: L0, "In-process
mock — Unit tests only." It never spawns a process, never touches the
filesystem or network, and never accepts a free-form command — it
returns a caller-configured ``AdapterResult`` (or simulates a timeout),
purely to exercise the broker's dispatch, parameter validation, and
audit wiring deterministically before any real worker exists.
"""

from __future__ import annotations

from aegis.broker.adapter import (
    AdapterDescriptor,
    AdapterResult,
    ToolAdapter,
    validate_parameters,
)
from aegis.domain.action import ActionRequest

__all__ = ["MockAdapter"]

_DEFAULT_RESULT = AdapterResult(exit_status="success", duration_seconds=0.01)


class MockAdapter(ToolAdapter):
    def __init__(
        self,
        descriptor: AdapterDescriptor,
        *,
        allowed_parameter_keys: frozenset[str] = frozenset(),
        result: AdapterResult = _DEFAULT_RESULT,
        simulate_timeout: bool = False,
    ) -> None:
        self.descriptor = descriptor
        self.allowed_parameter_keys = allowed_parameter_keys
        self._result = result
        self._simulate_timeout = simulate_timeout
        self.calls: list[ActionRequest] = []

    def run(self, request: ActionRequest, *, capability_ref: str) -> AdapterResult:
        validate_parameters(
            self.descriptor.id, request.parameters, allowed_keys=self.allowed_parameter_keys
        )
        self.calls.append(request)
        if self._simulate_timeout:
            return AdapterResult(
                exit_status="timeout",
                duration_seconds=float(self.descriptor.limits.timeout_seconds),
            )
        return self._result
