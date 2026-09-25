from __future__ import annotations

import pytest

from aegis.broker.adapter import AdapterDescriptor
from aegis.broker.mock import MockAdapter
from aegis.broker.registry import AdapterRegistry, DuplicateAdapterError, UnknownAdapterError
from aegis.core.actions import ActionResources


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


def test_adapter_registration_requires_action_contracts(scan_adapter: MockAdapter) -> None:
    registry = AdapterRegistry()
    adapter_without_contracts = MockAdapter(
        scan_adapter.descriptor, allowed_parameter_keys=frozenset({"ruleset_ref"})
    )
    with pytest.raises(ValueError, match="must register at least one action definition"):
        registry.register(adapter_without_contracts)


def test_action_contract_cannot_claim_more_resources_than_adapter(
    scan_adapter: MockAdapter,
) -> None:
    registry = AdapterRegistry()
    definition = scan_adapter.action_definitions[0].model_copy(
        update={"resources": ActionResources(timeout_seconds=301, cpu=2, memory_mb=2048)}
    )
    with pytest.raises(ValueError, match="must equal the adapter's declared limits"):
        registry.register(scan_adapter, action_definitions=(definition,))
    assert "semgrep.scan" not in registry
