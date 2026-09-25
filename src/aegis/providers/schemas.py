"""Structured task/context/proposal schemas for the provider boundary.

See docs/MODEL_STRATEGY.md "Provider abstraction", "Task roles, not
autonomous personalities", and "Structured-output rule". The model
receives a ``ReasoningTask`` plus a compact ``EvidenceContext`` and a
filtered list of ``ToolDescriptor``s, and returns a ``StructuredProposal``
— never a command, and never free text. A proposal is data the action
broker (a later change) evaluates through the policy engine; it carries
no authority of its own (docs/CONTROL_PLANE.md: "The model may supply
rationale. Rationale cannot override policy.").

This is a deliberately minimal context envelope for Change 3: a full
redaction/compaction context builder (docs/ARCHITECTURE.md's "Context
builder" component) is deferred to a later change.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Final, Literal

from pydantic import Field, model_validator

from aegis.domain.base import ActionId, AegisModel, CaseId, Reason, ToolId, Uri
from aegis.domain.policy import RiskTier

__all__ = [
    "EvidenceContext",
    "InferenceLimits",
    "ProposalKind",
    "ProposedAction",
    "ReasoningTask",
    "StructuredProposal",
    "TaskRole",
    "ToolDescriptor",
]

STRUCTURED_PROPOSAL_SCHEMA_VERSION: Final[Literal["aegis.structured_proposal/v1"]] = (
    "aegis.structured_proposal/v1"
)


class TaskRole(StrEnum):
    """The typed task roles from docs/MODEL_STRATEGY.md's task table."""

    TRIAGE = "triage"
    INVESTIGATION = "investigation"
    TOOL_SELECTION = "tool_selection"
    CONTAINMENT_PLANNING = "containment_planning"
    LOCALIZATION = "localization"
    PATCH_PLANNING = "patch_planning"
    PATCH_GENERATION = "patch_generation"
    REPORT_SYNTHESIS = "report_synthesis"


class ReasoningTask(AegisModel):
    """A system-authored task handed to the reasoning provider.

    ``instructions`` is system-authored (trusted); it is never derived
    from untrusted evidence content (docs/THREAT_MODEL.md's
    prompt-injection trust rule).
    """

    role: TaskRole
    case_id: CaseId
    instructions: Reason


class EvidenceContext(AegisModel):
    """A compact, provenance-linked view of case evidence for one call.

    Only stable evidence references are included, not raw content —
    matching docs/MODEL_STRATEGY.md's "Context construction": "Never
    send an entire environment or repository by default."
    """

    case_id: CaseId
    evidence_refs: tuple[Uri, ...] = ()
    summary: Reason


class ToolDescriptor(AegisModel):
    """The filtered tool description shown to the model.

    Only the broker sees the full execution descriptor
    (docs/TOOLS_AND_SANDBOXES.md "Tool descriptor"); this is
    intentionally a smaller, non-executable subset.
    """

    id: ToolId
    category: Reason
    risk_tier: RiskTier
    description: Reason


class InferenceLimits(AegisModel):
    """Per-call inference limits (docs/PRODUCT_REQUIREMENTS.md QR-CST-001)."""

    max_output_tokens: int = Field(gt=0)
    max_tool_calls: int = Field(gt=0)
    timeout_seconds: int = Field(gt=0)


class ProposalKind(StrEnum):
    """What kind of structured proposal the provider returned."""

    PROPOSE_ACTION = "propose_action"
    REFUSE = "refuse"
    ESCALATE = "escalate"


class ProposedAction(AegisModel):
    """A candidate action, in the shape the broker will later type as an
    ``ActionRequest`` (docs/CONTROL_PLANE.md's action-broker contract).

    This is intentionally not an ``ActionRequest`` itself: ``id``,
    ``case_id``, ``actor_id``, ``role``, and ``requested_at`` are
    broker-assigned, not model-supplied (SR-AUT-004: the broker is the
    only effectful path from reasoning to tools).
    """

    action_type: ActionId
    target_ref: Uri
    adapter: ToolId
    parameters: dict[str, Any] = Field(default_factory=dict)
    expected_evidence: tuple[str, ...] = ()
    reason: Reason


class StructuredProposal(AegisModel):
    """The versioned, schema-validated output of a reasoning call.

    Exactly one of ``PROPOSE_ACTION`` (with ``action`` set) or
    ``REFUSE``/``ESCALATE`` (with ``action`` unset) is valid — this is
    the concrete "response schema" docs/MODEL_STRATEGY.md requires every
    reasoning call to validate against.
    """

    schema_version: Literal["aegis.structured_proposal/v1"] = STRUCTURED_PROPOSAL_SCHEMA_VERSION
    kind: ProposalKind
    action: ProposedAction | None = None
    rationale: Reason

    @model_validator(mode="after")
    def _action_presence_matches_kind(self) -> StructuredProposal:
        if self.kind is ProposalKind.PROPOSE_ACTION and self.action is None:
            raise ValueError("a 'propose_action' proposal must include an action")
        if self.kind is not ProposalKind.PROPOSE_ACTION and self.action is not None:
            raise ValueError(f"a '{self.kind.value}' proposal must not include an action")
        return self
