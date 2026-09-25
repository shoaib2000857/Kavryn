from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aegis.core.capability import (
    Capability,
    CapabilityAuthority,
    CapabilityDeniedError,
    capability_parameters_digest,
)
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole, Digest

NOW = datetime(2026, 9, 25, tzinfo=UTC)


def _request(**updates: object) -> ActionRequest:
    values: dict[str, object] = {
        "id": "request-1",
        "case_id": "AGE-0001",
        "actor_id": "agent:test",
        "role": ActorRole.REASONING_RUNTIME,
        "action_type": "range.contain",
        "target_ref": "service://range/api",
        "adapter": "range.proxy",
        "parameters": {"pattern": "traversal"},
        "reason": "Contain the observed synthetic attack.",
        "requested_at": NOW,
    }
    values.update(updates)
    return ActionRequest.model_validate(values)


def _capability(**updates: object) -> Capability:
    values: dict[str, object] = {
        "id": "cap-1",
        "issuer": "control:authority",
        "subject": "agent:test",
        "case_id": "AGE-0001",
        "transaction_id": "tx-1",
        "scope_digest": Digest(digest="a" * 64),
        "action_type": "range.contain",
        "adapter": "range.proxy",
        "target_ref": "service://range/api",
        "risk_tier": "r3_reversible_response",
        "parameters_digest": capability_parameters_digest({"pattern": "traversal"}),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=1),
        "single_use": True,
        "max_uses": 1,
    }
    values.update(updates)
    return Capability.model_validate(values)


def test_capability_is_case_transaction_actor_action_adapter_target_and_parameter_bound() -> None:
    authority = CapabilityAuthority()
    authority.issue(_capability())
    grant = authority.consume("cap-1", _request(), transaction_id="tx-1", now=NOW)
    assert grant.id == "cap-1"


@pytest.mark.parametrize(
    ("request_changes", "transaction_id"),
    [
        ({"case_id": "AGE-0002"}, "tx-1"),
        ({"actor_id": "agent:other"}, "tx-1"),
        ({"action_type": "scan.run"}, "tx-1"),
        ({"adapter": "other.scan"}, "tx-1"),
        ({"target_ref": "service://range/other"}, "tx-1"),
        ({"parameters": {"pattern": "other"}}, "tx-1"),
        ({}, "tx-2"),
    ],
)
def test_binding_mismatch_is_denied(
    request_changes: dict[str, object], transaction_id: str
) -> None:
    authority = CapabilityAuthority()
    authority.issue(_capability())
    with pytest.raises(CapabilityDeniedError, match="bindings"):
        authority.consume(
            "cap-1", _request(**request_changes), transaction_id=transaction_id, now=NOW
        )


def test_capability_expiry_revocation_and_single_use_replay_are_enforced() -> None:
    authority = CapabilityAuthority()
    authority.issue(_capability())
    with pytest.raises(CapabilityDeniedError, match="not currently valid"):
        authority.consume(
            "cap-1", _request(), transaction_id="tx-1", now=NOW + timedelta(minutes=1)
        )

    authority.consume("cap-1", _request(), transaction_id="tx-1", now=NOW)
    with pytest.raises(CapabilityDeniedError, match="exhausted"):
        authority.consume("cap-1", _request(), transaction_id="tx-1", now=NOW)

    authority.issue(_capability(id="cap-2", transaction_id="tx-2"))
    authority.revoke("cap-2", at=NOW + timedelta(seconds=1))
    assert authority.is_revoked("cap-2")
    with pytest.raises(CapabilityDeniedError, match="revoked"):
        authority.consume(
            "cap-2", _request(), transaction_id="tx-2", now=NOW + timedelta(seconds=2)
        )


def test_duplicate_capability_ids_are_rejected() -> None:
    authority = CapabilityAuthority()
    authority.issue(_capability())
    with pytest.raises(CapabilityDeniedError, match="already been issued"):
        authority.issue(_capability())
