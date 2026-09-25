from __future__ import annotations

import pytest

from aegis.broker.adapter import AdapterDescriptor
from aegis.broker.mock import MockAdapter
from aegis.broker.registry import AdapterRegistry, DuplicateAdapterError, UnknownAdapterError


def test_registered_adapter_can_be_retrieved_by_id(scan_adapter: MockAdapter) -> None:
    registry = AdapterRegistry()
    registry.register(scan_adapter)
    assert registry.get("semgrep.scan") is scan_adapter
    assert "semgrep.scan" in registry


def test_unknown_adapter_id_raises(registry: AdapterRegistry) -> None:
    with pytest.raises(UnknownAdapterError):
        registry.get("does.not-exist")


def test_registering_the_same_adapter_id_twice_raises(
    scan_descriptor: AdapterDescriptor, scan_adapter: MockAdapter
) -> None:
    registry = AdapterRegistry()
    registry.register(scan_adapter)
    duplicate = MockAdapter(scan_descriptor)
    with pytest.raises(DuplicateAdapterError):
        registry.register(duplicate)


def test_contains_reports_false_for_unregistered_id(registry: AdapterRegistry) -> None:
    assert "unregistered.adapter" not in registry
