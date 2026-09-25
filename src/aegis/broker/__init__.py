"""The typed action broker (docs/IMPLEMENTATION_HANDOFF.md Change 4).

The only effectful path from a proposed action to a tool: validates and
authorizes an ``ActionRequest`` through the Change-2 policy engine,
dispatches to a registered typed adapter only when permitted, and
records every request, decision, and result to the audit sink. No
generic shell adapter exists anywhere in this package.
"""

from aegis.broker.adapter import (
    AdapterDescriptor,
    AdapterLimits,
    AdapterPermissions,
    AdapterResult,
    ParameterValidationError,
    ToolAdapter,
    validate_parameters,
)
from aegis.broker.broker import ActionBroker, BrokerError, BrokerOutcome
from aegis.broker.mock import MockAdapter
from aegis.broker.registry import AdapterRegistry, DuplicateAdapterError, UnknownAdapterError

__all__ = [
    "ActionBroker",
    "AdapterDescriptor",
    "AdapterLimits",
    "AdapterPermissions",
    "AdapterRegistry",
    "AdapterResult",
    "BrokerError",
    "BrokerOutcome",
    "DuplicateAdapterError",
    "MockAdapter",
    "ParameterValidationError",
    "ToolAdapter",
    "UnknownAdapterError",
    "validate_parameters",
]
