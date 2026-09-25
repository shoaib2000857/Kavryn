"""The adapter registry.

See docs/IMPLEMENTATION_HANDOFF.md Change 4 ("registry and descriptor
validation") and docs/TOOLS_AND_SANDBOXES.md's "Retrieval and
selection" pipeline. The registry is the only place an adapter is
looked up by id; an unregistered adapter id is always a hard failure,
never a silent no-op.
"""

from __future__ import annotations

from aegis.broker.adapter import ToolAdapter

__all__ = ["AdapterRegistry", "DuplicateAdapterError", "UnknownAdapterError"]


class DuplicateAdapterError(ValueError):
    """Raised when registering an adapter id that is already registered."""


class UnknownAdapterError(KeyError):
    """Raised when looking up an adapter id that was never registered."""


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        adapter_id = adapter.descriptor.id
        if adapter_id in self._adapters:
            raise DuplicateAdapterError(f"adapter '{adapter_id}' is already registered")
        self._adapters[adapter_id] = adapter

    def get(self, adapter_id: str) -> ToolAdapter:
        try:
            return self._adapters[adapter_id]
        except KeyError:
            raise UnknownAdapterError(adapter_id) from None

    def __contains__(self, adapter_id: str) -> bool:
        return adapter_id in self._adapters
