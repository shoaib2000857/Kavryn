from __future__ import annotations

import pytest

from aegis.domain.policy import RiskTier
from aegis.providers.schemas import (
    EvidenceContext,
    InferenceLimits,
    ReasoningTask,
    TaskRole,
    ToolDescriptor,
)


@pytest.fixture
def task() -> ReasoningTask:
    return ReasoningTask(
        role=TaskRole.TRIAGE,
        case_id="AGE-0001",
        instructions="Form an incident hypothesis from the observed events.",
    )


@pytest.fixture
def context() -> EvidenceContext:
    return EvidenceContext(
        case_id="AGE-0001",
        evidence_refs=("asset://demo-api",),
        summary="Suspicious file access observed against demo-api.",
    )


@pytest.fixture
def tools() -> tuple[ToolDescriptor, ...]:
    return (
        ToolDescriptor(
            id="scan.run",
            category="static-analysis",
            risk_tier=RiskTier.R1_ANALYZE,
            description="Run a static analysis scan against the workspace.",
        ),
    )


@pytest.fixture
def limits() -> InferenceLimits:
    return InferenceLimits(max_output_tokens=2000, max_tool_calls=5, timeout_seconds=60)
