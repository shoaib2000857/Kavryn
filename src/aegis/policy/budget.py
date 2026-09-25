"""Budget accounting for the policy engine.

See docs/CONTROL_PLANE.md "Budget behavior" and
docs/PRODUCT_REQUIREMENTS.md QR-CST-001. ``BudgetUsage`` is a plain
snapshot of consumption-so-far for a case; the policy decision function
is pure and takes it as an input rather than reading or mutating any
hidden state, so budget bookkeeping (incrementing usage after a
permitted action) is the caller's responsibility (the action broker,
in a later change).
"""

from __future__ import annotations

from pydantic import Field

from aegis.domain.base import AegisModel
from aegis.domain.scope import Budgets

__all__ = ["BudgetUsage", "exhausted_dimensions"]


class BudgetUsage(AegisModel):
    """Cumulative resource consumption recorded for a case so far."""

    tool_calls: int = Field(default=0, ge=0)
    model_tokens: int = Field(default=0, ge=0)
    wall_time_seconds: int = Field(default=0, ge=0)
    spend_usd: float = Field(default=0, ge=0)


def exhausted_dimensions(budgets: Budgets, usage: BudgetUsage) -> tuple[str, ...]:
    """Return the names of every budget dimension already at or over its limit.

    An empty tuple means the case has remaining budget on every
    dimension. Any exhausted dimension is sufficient grounds to deny
    further actions until the case's budget is explicitly extended
    (docs/CONTROL_PLANE.md: "the workflow must not disguise retries as
    new subtasks or create new identities to evade limits").
    """
    exceeded = []
    if usage.tool_calls >= budgets.tool_calls:
        exceeded.append("tool_calls")
    if usage.model_tokens >= budgets.model_tokens:
        exceeded.append("model_tokens")
    if usage.wall_time_seconds >= budgets.wall_time_seconds:
        exceeded.append("wall_time_seconds")
    if usage.spend_usd >= budgets.spend_usd:
        exceeded.append("spend_usd")
    return tuple(exceeded)
