"""The ``ReasoningProvider`` protocol.

See docs/MODEL_STRATEGY.md "Provider abstraction". Any model backend —
stub, replay, or a future hosted/self-hosted adapter — implements this
one interface. The provider returns a structured proposal; it never
executes an action itself (docs/ARCHITECTURE.md: "Model provider |
Returns structured proposals | Untrusted adviser").
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from aegis.providers.schemas import (
    EvidenceContext,
    InferenceLimits,
    ReasoningTask,
    StructuredProposal,
    ToolDescriptor,
)

__all__ = ["ReasoningProvider"]


@runtime_checkable
class ReasoningProvider(Protocol):
    async def propose(
        self,
        task: ReasoningTask,
        context: EvidenceContext,
        tools: tuple[ToolDescriptor, ...],
        limits: InferenceLimits,
    ) -> StructuredProposal: ...
