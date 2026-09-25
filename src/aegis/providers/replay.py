"""``ReplayProvider``: deterministic tests using recorded responses.

See docs/MODEL_STRATEGY.md: "``ReplayProvider`` for deterministic tests
using recorded responses." Returns a fixed sequence of proposals in
order, one per call; exhausting the sequence is a hard error rather than
looping or fabricating a response, so a test that calls it more times
than expected fails loudly instead of masking a bug.
"""

from __future__ import annotations

from aegis.providers.schemas import (
    EvidenceContext,
    InferenceLimits,
    ReasoningTask,
    StructuredProposal,
    ToolDescriptor,
)

__all__ = ["ReplayExhaustedError", "ReplayProvider"]


class ReplayExhaustedError(RuntimeError):
    """Raised when more calls are made than recorded responses exist."""


class ReplayProvider:
    """Replays ``responses`` in order, one per call to ``propose``."""

    def __init__(self, responses: tuple[StructuredProposal, ...]) -> None:
        self._responses = responses
        self._index = 0
        self.calls: list[ReasoningTask] = []

    async def propose(
        self,
        task: ReasoningTask,
        context: EvidenceContext,
        tools: tuple[ToolDescriptor, ...],
        limits: InferenceLimits,
    ) -> StructuredProposal:
        self.calls.append(task)
        if self._index >= len(self._responses):
            raise ReplayExhaustedError(f"replay exhausted after {self._index} recorded response(s)")
        response = self._responses[self._index]
        self._index += 1
        return response
