from __future__ import annotations

import asyncio

import pytest

from aegis.providers.replay import ReplayExhaustedError, ReplayProvider
from aegis.providers.schemas import (
    EvidenceContext,
    InferenceLimits,
    ProposalKind,
    ReasoningTask,
    StructuredProposal,
    ToolDescriptor,
)

FIRST = StructuredProposal(kind=ProposalKind.REFUSE, rationale="first recorded response")
SECOND = StructuredProposal(kind=ProposalKind.ESCALATE, rationale="second recorded response")


def test_replay_returns_responses_in_order(
    task: ReasoningTask,
    context: EvidenceContext,
    tools: tuple[ToolDescriptor, ...],
    limits: InferenceLimits,
) -> None:
    provider = ReplayProvider((FIRST, SECOND))
    assert asyncio.run(provider.propose(task, context, tools, limits)) == FIRST
    assert asyncio.run(provider.propose(task, context, tools, limits)) == SECOND


def test_replay_raises_when_exhausted(
    task: ReasoningTask,
    context: EvidenceContext,
    tools: tuple[ToolDescriptor, ...],
    limits: InferenceLimits,
) -> None:
    provider = ReplayProvider((FIRST,))
    asyncio.run(provider.propose(task, context, tools, limits))
    with pytest.raises(ReplayExhaustedError):
        asyncio.run(provider.propose(task, context, tools, limits))


def test_replay_with_empty_sequence_raises_on_first_call(
    task: ReasoningTask,
    context: EvidenceContext,
    tools: tuple[ToolDescriptor, ...],
    limits: InferenceLimits,
) -> None:
    provider = ReplayProvider(())
    with pytest.raises(ReplayExhaustedError):
        asyncio.run(provider.propose(task, context, tools, limits))


def test_replay_records_every_call(
    task: ReasoningTask,
    context: EvidenceContext,
    tools: tuple[ToolDescriptor, ...],
    limits: InferenceLimits,
) -> None:
    provider = ReplayProvider((FIRST, SECOND))
    asyncio.run(provider.propose(task, context, tools, limits))
    asyncio.run(provider.propose(task, context, tools, limits))
    assert provider.calls == [task, task]
