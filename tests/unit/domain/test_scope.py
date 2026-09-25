from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from aegis.domain import (
    ActionsPolicy,
    NetworkAllowRule,
    NetworkPolicy,
    ScopePolicy,
    Targets,
)


def test_valid_scope_policy_round_trips(scope_policy: ScopePolicy) -> None:
    restored = ScopePolicy.model_validate_json(scope_policy.model_dump_json())
    assert restored == scope_policy


def test_network_default_is_always_deny(scope_policy: ScopePolicy) -> None:
    assert scope_policy.network.default == "deny"


def test_network_policy_rejects_non_deny_default() -> None:
    with pytest.raises(ValidationError):
        NetworkPolicy.model_validate({"default": "allow", "allow": []})


def test_network_allow_rule_rejects_out_of_range_port() -> None:
    with pytest.raises(ValidationError):
        NetworkAllowRule(destination="demo-api-range", ports=(70000,))


def test_network_allow_rule_requires_at_least_one_port() -> None:
    with pytest.raises(ValidationError):
        NetworkAllowRule(destination="demo-api-range", ports=())


def test_targets_requires_at_least_one_entry() -> None:
    with pytest.raises(ValidationError):
        Targets()


def test_actions_policy_rejects_action_listed_in_two_buckets() -> None:
    with pytest.raises(ValidationError, match="ambiguous action disposition"):
        ActionsPolicy(auto=("scan.run",), approval=("scan.run",))


def test_actions_policy_allows_same_action_repeated_in_one_bucket() -> None:
    policy = ActionsPolicy(auto=("scan.run", "scan.run"))
    assert policy.auto == ("scan.run", "scan.run")


@pytest.mark.parametrize(
    "bad_action_id",
    ["scan", "Scan.Run", "scan run", "scan.run; rm -rf /", ""],
)
def test_action_id_rejects_non_dotted_or_shell_like_values(
    scope_policy_kwargs: dict[str, Any], bad_action_id: str
) -> None:
    kwargs = dict(scope_policy_kwargs)
    kwargs["actions"] = {"auto": [bad_action_id]}
    with pytest.raises(ValidationError):
        ScopePolicy(**kwargs)


def test_scope_policy_rejects_zero_or_negative_budget(
    scope_policy_kwargs: dict[str, Any],
) -> None:
    kwargs = dict(scope_policy_kwargs)
    kwargs["budgets"] = {
        "tool_calls": 0,
        "model_tokens": 100_000,
        "wall_time_seconds": 3600,
        "spend_usd": 20,
    }
    with pytest.raises(ValidationError):
        ScopePolicy(**kwargs)


def test_scope_policy_rejects_negative_spend(scope_policy_kwargs: dict[str, Any]) -> None:
    kwargs = dict(scope_policy_kwargs)
    kwargs["budgets"] = {
        "tool_calls": 10,
        "model_tokens": 1000,
        "wall_time_seconds": 60,
        "spend_usd": -1,
    }
    with pytest.raises(ValidationError):
        ScopePolicy(**kwargs)


def test_scope_policy_rejects_unversioned_policy(scope_policy_kwargs: dict[str, Any]) -> None:
    kwargs = dict(scope_policy_kwargs)
    kwargs["version"] = 0
    with pytest.raises(ValidationError):
        ScopePolicy(**kwargs)
