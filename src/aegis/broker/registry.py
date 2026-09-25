"""The adapter registry.

See docs/IMPLEMENTATION_HANDOFF.md Change 4 ("registry and descriptor
validation") and docs/TOOLS_AND_SANDBOXES.md's "Retrieval and
selection" pipeline. The registry is the only place an adapter is
looked up by id; an unregistered adapter id is always a hard failure,
never a silent no-op.
"""

from __future__ import annotations

from aegis.broker.adapter import ToolAdapter
from aegis.core.actions import ActionCatalog, ActionDefinition
from aegis.domain.action import ActionRequest

__all__ = ["AdapterRegistry", "DuplicateAdapterError", "UnknownAdapterError"]


class DuplicateAdapterError(ValueError):
    """Raised when registering an adapter id that is already registered."""


class UnknownAdapterError(KeyError):
    """Raised when looking up an adapter id that was never registered."""


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {}
        self._actions = ActionCatalog()

    def register(
        self, adapter: ToolAdapter, *, action_definitions: tuple[ActionDefinition, ...] = ()
    ) -> None:
        adapter_id = adapter.descriptor.id
        if adapter_id in self._adapters:
            raise DuplicateAdapterError(f"adapter '{adapter_id}' is already registered")
        definitions = action_definitions or getattr(adapter, "action_definitions", ())
        if not definitions:
            raise ValueError(f"adapter '{adapter_id}' must register at least one action definition")
        for definition in definitions:
            self._actions.validate_registration(definition, adapter.descriptor)
        registered: list[ActionDefinition] = []
        try:
            for definition in definitions:
                self._actions.register(definition)
                registered.append(definition)
        except ValueError:
            for definition in registered:
                self._actions.unregister(definition.action_type)
            raise
        self._adapters[adapter_id] = adapter

    def get(self, adapter_id: str) -> ToolAdapter:
        try:
            return self._adapters[adapter_id]
        except KeyError:
            raise UnknownAdapterError(adapter_id) from None

    def __contains__(self, adapter_id: str) -> bool:
        return adapter_id in self._adapters

    def validate_request(self, request: ActionRequest) -> ActionDefinition:
        """Resolve and validate the versioned action contract before dispatch."""
        return self._actions.validate_parameters(
            request.action_type, request.adapter, request.parameters
        )

    def validate_output(self, definition: ActionDefinition, output: dict[str, object]) -> None:
        self._actions.validate_output(definition, output)

    def action_definition(self, action_type: str) -> ActionDefinition:
        return self._actions.get(action_type)
