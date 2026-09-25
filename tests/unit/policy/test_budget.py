from __future__ import annotations

from aegis.domain.scope import Budgets
from aegis.policy.budget import BudgetUsage, exhausted_dimensions

BUDGETS = Budgets(tool_calls=10, model_tokens=1000, wall_time_seconds=60, spend_usd=5)


def test_no_dimension_exhausted_when_usage_is_zero() -> None:
    assert exhausted_dimensions(BUDGETS, BudgetUsage()) == ()


def test_no_dimension_exhausted_when_usage_is_below_limit() -> None:
    usage = BudgetUsage(tool_calls=9, model_tokens=999, wall_time_seconds=59, spend_usd=4.99)
    assert exhausted_dimensions(BUDGETS, usage) == ()


def test_tool_calls_exhausted_at_exact_limit() -> None:
    """Repeated action-budget exhaustion: hitting the limit exactly denies
    further actions rather than allowing one more (off-by-one safety)."""
    usage = BudgetUsage(tool_calls=10)
    assert "tool_calls" in exhausted_dimensions(BUDGETS, usage)


def test_multiple_dimensions_can_be_exhausted_simultaneously() -> None:
    usage = BudgetUsage(tool_calls=10, model_tokens=1000, wall_time_seconds=60, spend_usd=5)
    exceeded = exhausted_dimensions(BUDGETS, usage)
    assert set(exceeded) == {"tool_calls", "model_tokens", "wall_time_seconds", "spend_usd"}


def test_usage_over_limit_is_still_reported_exhausted() -> None:
    usage = BudgetUsage(tool_calls=999)
    assert "tool_calls" in exhausted_dimensions(BUDGETS, usage)
