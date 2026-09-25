from __future__ import annotations

import asyncio

from aegis.providers.schemas import (
    EvidenceContext,
    InferenceLimits,
    ProposalKind,
    ReasoningTask,
    StructuredProposal,
    ToolDescriptor,
)
from aegis.providers.stub import StubProvider


def test_stub_provider_defaults_to_a_safe_refusal(
    task: ReasoningTask,
    context: EvidenceContext,
    tools: tuple[ToolDescriptor, ...],
    limits: InferenceLimits,
) -> None:
    provider = StubProvider()
    proposal = asyncio.run(provider.propose(task, context, tools, limits))
    assert proposal.kind is ProposalKind.REFUSE


def test_stub_provider_returns_the_configured_response(
    task: ReasoningTask,
    context: EvidenceContext,
    tools: tuple[ToolDescriptor, ...],
    limits: InferenceLimits,
) -> None:
    fixed = StructuredProposal(kind=ProposalKind.ESCALATE, rationale="fixed test response")
    provider = StubProvider(response=fixed)
    proposal = asyncio.run(provider.propose(task, context, tools, limits))
    assert proposal == fixed


def test_stub_provider_records_every_call(
    task: ReasoningTask,
    context: EvidenceContext,
    tools: tuple[ToolDescriptor, ...],
    limits: InferenceLimits,
) -> None:
    provider = StubProvider()
    asyncio.run(provider.propose(task, context, tools, limits))
    asyncio.run(provider.propose(task, context, tools, limits))
    assert provider.calls == [task, task]


def test_stub_provider_ignores_input_and_is_deterministic(
    task: ReasoningTask,
    context: EvidenceContext,
    tools: tuple[ToolDescriptor, ...],
    limits: InferenceLimits,
) -> None:
    provider = StubProvider()
    first = asyncio.run(provider.propose(task, context, tools, limits))
    second = asyncio.run(provider.propose(task, context, (), limits))
    assert first == second
