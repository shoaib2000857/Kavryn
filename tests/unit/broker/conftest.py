from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

import pytest

from aegis.broker.adapter import AdapterDescriptor, AdapterLimits, AdapterPermissions
from aegis.broker.mock import MockAdapter
from aegis.broker.registry import AdapterRegistry
from aegis.core.actions import (
    ActionDefinition,
    ActionParameter,
    ActionResources,
    ActionSideEffect,
    ActionValueType,
    VerificationContract,
)
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole
from aegis.domain.policy import RiskTier
from aegis.evidence.audit import InMemoryAuditSink
from aegis.evidence.store import InMemoryArtifactStore


@pytest.fixture
def scan_descriptor() -> AdapterDescriptor:
    return AdapterDescriptor(
        id="semgrep.scan",
        version=1,
        category="static-analysis",
        permissions=AdapterPermissions(filesystem="read-target"),
        risk_tier=RiskTier.R1_ANALYZE,
        limits=AdapterLimits(timeout_seconds=300, cpu=2, memory_mb=2048),
        parser="semgrep-sarif-v1",
    )


@pytest.fixture
def scan_adapter(scan_descriptor: AdapterDescriptor) -> MockAdapter:
    definition = ActionDefinition(
        action_type="scan.run",
        version=1,
        adapter_id=scan_descriptor.id,
        description="Run the test static analysis adapter.",
        inputs=(
            ActionParameter(
                name="ruleset_ref",
                value_type=ActionValueType.STRING,
                description="Immutable ruleset reference.",
            ),
        ),
        risk_tier=scan_descriptor.risk_tier,
        side_effects=(ActionSideEffect.READ,),
        filesystem="read-target",
        resources=ActionResources(timeout_seconds=300, cpu=2, memory_mb=2048),
        verification=VerificationContract(required=False),
    )
    deployment_definition = definition.model_copy(
        update={
            "action_type": "deployment.rollout",
            "description": "Synthetic approval-gate test action.",
            "risk_tier": RiskTier.R4_CHANGE,
        }
    )
    return MockAdapter(
        scan_descriptor,
        allowed_parameter_keys=frozenset({"ruleset_ref"}),
        action_definitions=(definition, deployment_definition),
    )


@pytest.fixture
def registry(scan_adapter: MockAdapter) -> AdapterRegistry:
    reg = AdapterRegistry()
    reg.register(scan_adapter)
    return reg


@pytest.fixture
def audit_sink() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture
def artifact_store() -> InMemoryArtifactStore:
    return InMemoryArtifactStore()


def _make_request(now: datetime, **overrides: Any) -> ActionRequest:
    defaults: dict[str, Any] = {
        "id": "req-0001",
        "case_id": "AGE-0001",
        "actor_id": "reasoning_runtime:v1",
        "role": ActorRole.REASONING_RUNTIME,
        "action_type": "scan.run",
        "target_ref": "workspace://AGE-0001/candidate/x",
        "adapter": "semgrep.scan",
        "parameters": {"ruleset_ref": "immutable-artifact://rules/python"},
        "reason": "scan the candidate workspace",
        "requested_at": now,
    }
    defaults.update(overrides)
    return ActionRequest(**defaults)


@pytest.fixture
def make_request() -> Callable[..., ActionRequest]:
    """A factory fixture: ``make_request(now, **overrides) -> ActionRequest``."""
    return _make_request
