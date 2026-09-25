"""The reasoning-provider boundary (docs/IMPLEMENTATION_HANDOFF.md Change 3, Change 8).

Contains the ``ReasoningProvider`` protocol, structured task/context/
proposal schemas, ``StubProvider``/``ReplayProvider``, bounded
structured-response parsing, and (Change 8) a generic
``HostedOpenAICompatibleProvider``. docs/OPEN_QUESTIONS.md OQ-004
("Which hosted model provider/API account and spend cap?") is
owner-resolved as of 2026-09-06 (docs/DECISIONS.md ADR-031) to permit a
hosted provider implementation — but as of this change no working
direct-API credential has been obtained (the offered key was rejected
by client-fingerprint gating, unrelated to key validity), so the
default provider for every test in this repository, including Change
8's full-case run, remains stub/replay.
"""

from aegis.providers.base import ReasoningProvider
from aegis.providers.hosted import (
    HostedApiError,
    HostedOpenAICompatibleProvider,
    HostedProviderConfig,
)
from aegis.providers.parsing import (
    ProposalParseError,
    RepairFn,
    parse_structured_proposal,
    parse_with_bounded_repair,
)
from aegis.providers.replay import ReplayExhaustedError, ReplayProvider
from aegis.providers.schemas import (
    EvidenceContext,
    InferenceLimits,
    ProposalKind,
    ProposedAction,
    ReasoningTask,
    StructuredProposal,
    TaskRole,
    ToolDescriptor,
)
from aegis.providers.stub import StubProvider

__all__ = [
    "EvidenceContext",
    "HostedApiError",
    "HostedOpenAICompatibleProvider",
    "HostedProviderConfig",
    "InferenceLimits",
    "ProposalKind",
    "ProposalParseError",
    "ProposedAction",
    "ReasoningProvider",
    "ReasoningTask",
    "RepairFn",
    "ReplayExhaustedError",
    "ReplayProvider",
    "StructuredProposal",
    "StubProvider",
    "TaskRole",
    "ToolDescriptor",
    "parse_structured_proposal",
    "parse_with_bounded_repair",
]
