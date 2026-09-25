"""The ActionRequest record: a structured, typed proposal for one action.

See docs/CONTROL_PLANE.md "Action broker contract". An ActionRequest is
what the reasoning plane may submit; it is data, not a command, and it
carries no risk tier, capability, or budget of its own. Those are
assigned by the deterministic policy engine (docs/IMPLEMENTATION_HANDOFF.md
Change 2) and recorded on a ``PolicyDecision``
(docs/ARCHITECTURE.md: "Risk is determined by the action and context,
not by the model's label.").
"""

from __future__ import annotations

from typing import Any, Final, Literal

from pydantic import Field, model_validator

from aegis.domain.base import (
    ActionId,
    ActorId,
    ActorRole,
    AegisModel,
    AwareDatetime,
    CaseId,
    Reason,
    RecordId,
    ToolId,
    Uri,
)

__all__ = ["ActionRequest"]

ACTION_REQUEST_SCHEMA_VERSION: Final[Literal["aegis.action_request/v1"]] = "aegis.action_request/v1"

# Parameter keys that would let a request smuggle a raw command or shell
# invocation past the typed-adapter boundary (ADR-006, docs/THREAT_MODEL.md
# T02). The adapter's own validated schema constructs the real command;
# the model is never permitted to supply one of these fields.
_FORBIDDEN_PARAMETER_KEYS = frozenset(
    {"command", "cmd", "shell", "argv", "exec", "script", "raw_command"}
)


class ActionRequest(AegisModel):
    """A structured request from the reasoning plane to the action broker."""

    schema_version: Literal["aegis.action_request/v1"] = ACTION_REQUEST_SCHEMA_VERSION
    id: RecordId
    case_id: CaseId
    actor_id: ActorId
    role: ActorRole
    action_type: ActionId
    target_ref: Uri
    adapter: ToolId
    parameters: dict[str, Any] = Field(default_factory=dict)
    expected_evidence: tuple[str, ...] = ()
    reason: Reason
    requested_at: AwareDatetime

    @model_validator(mode="after")
    def _reject_forbidden_parameters(self) -> ActionRequest:
        offending = _FORBIDDEN_PARAMETER_KEYS.intersection(self.parameters)
        if offending:
            raise ValueError(
                f"action request parameters may not include raw command fields: {sorted(offending)}"
            )
        return self
