"""``StubProvider``: a deterministic, no-model reasoning provider.

See docs/MODEL_STRATEGY.md: "``StubProvider`` for unit tests that do not
require a model." Returns a fixed, caller-supplied proposal (or a safe
refusal by default) regardless of input — useful for exercising
orchestration and control-plane code paths without any model backend.
"""

from __future__ import annotations

from aegis.providers.schemas import (
    EvidenceContext,
    InferenceLimits,
    ProposalKind,
    ReasoningTask,
    StructuredProposal,
    ToolDescriptor,
)

__all__ = ["StubProvider"]

_DEFAULT_REFUSAL = StructuredProposal(
    kind=ProposalKind.REFUSE,
    rationale="stub provider: no reasoning backend configured",
)


class StubProvider:
    """Always returns ``response`` (default: a safe refusal), ignoring input."""

    def __init__(self, response: StructuredProposal = _DEFAULT_REFUSAL) -> None:
        self._response = response
        self.calls: list[ReasoningTask] = []

    async def propose(
        self,
        task: ReasoningTask,
        context: EvidenceContext,
        tools: tuple[ToolDescriptor, ...],
        limits: InferenceLimits,
    ) -> StructuredProposal:
        self.calls.append(task)
        return self._response
