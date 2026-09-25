from __future__ import annotations

from pathlib import Path

import pytest

from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole
from aegis.range.adapter import ProxyRuleAdapter
from aegis.range.containment import ContainmentRule, read_rules


def _request() -> ActionRequest:
    from datetime import UTC, datetime

    return ActionRequest(
        id="contain-object-auth",
        case_id="AGE-OBJECT-AUTH-01",
        actor_id="control:test",
        role=ActorRole.CONTROL_PLANE,
        action_type="contain.rate_limit",
        target_ref="service://object-auth-range",
        adapter="range.proxy",
        parameters={"operation": "apply"},
        expected_evidence=("attack_blocked",),
        reason="Apply fixed range containment policy for the test scenario.",
        requested_at=datetime.now(UTC),
    )


def test_adapter_applies_owner_configured_fixed_rule_set(tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.json"
    adapter = ProxyRuleAdapter(
        str(rules_file),
        deny_query_patterns=(r"^/documents/",),
        deny_authorization_patterns=(r"^Bearer test-token-bob$",),
        rule_set_id="object-auth-endpoint-isolation",
    )

    result = adapter.run(_request(), capability_ref="checked-by-broker")

    assert result.exit_status == "success"
    assert result.output["rule_set"] == "object-auth-endpoint-isolation"
    assert read_rules(str(rules_file)) == ContainmentRule(
        deny_query_patterns=(r"^/documents/",),
        deny_authorization_patterns=(r"^Bearer test-token-bob$",),
    )


@pytest.mark.parametrize(
    ("patterns", "rule_set_id"),
    [
        ((), "empty"),
        (("x" * 257,), "oversized-pattern"),
        (("[",), "invalid-regex"),
        ((r"^/documents/",), "x" * 81),
    ],
)
def test_adapter_rejects_invalid_owner_config(patterns: tuple[str, ...], rule_set_id: str) -> None:
    with pytest.raises(ValueError):
        ProxyRuleAdapter(
            "/tmp/aegis-rules-test.json",
            deny_query_patterns=patterns,
            rule_set_id=rule_set_id,
        )


def test_adapter_accepts_identity_only_temporary_containment(tmp_path: Path) -> None:
    adapter = ProxyRuleAdapter(
        str(tmp_path / "rules.json"),
        deny_query_patterns=(),
        deny_authorization_patterns=(r"^Bearer test-token-bob$",),
        rule_set_id="revoke-synthetic-bob-session",
    )

    result = adapter.run(_request(), capability_ref="checked-by-broker")

    assert result.exit_status == "success"
    assert read_rules(str(tmp_path / "rules.json")).deny_authorization_patterns == (
        r"^Bearer test-token-bob$",
    )
