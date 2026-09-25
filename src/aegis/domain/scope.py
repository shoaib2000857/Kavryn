"""The ScopePolicy record: the case-specific authorization boundary.

Modeled after the conceptual schema in docs/CONTROL_PLANE.md. Every
field here is an accepted-architecture concept (targets, network,
filesystem, tools, actions, budgets); this change adds no policy
*evaluation* logic (that is docs/IMPLEMENTATION_HANDOFF.md Change 2) but
does encode a few fail-closed structural invariants directly in the
schema, per docs/PRODUCT_REQUIREMENTS.md FR-SCP-002/FR-SCP-003.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal

from pydantic import Field, StringConstraints, model_validator

from aegis.domain.base import ActionId, AegisModel, AwareDatetime, CaseId, ToolId, Uri

__all__ = [
    "ActionsPolicy",
    "Authorization",
    "Budgets",
    "FilesystemPolicy",
    "NetworkAllowRule",
    "NetworkPolicy",
    "RepositoryTarget",
    "ScopePolicy",
    "ServiceTarget",
    "Targets",
    "ToolsPolicy",
]

SCOPE_POLICY_SCHEMA_VERSION: Final[Literal["aegis.scope_policy/v1"]] = "aegis.scope_policy/v1"

_Port = Annotated[int, Field(ge=1, le=65535)]
_Id = Annotated[str, StringConstraints(min_length=1, max_length=200)]


class Authorization(AegisModel):
    """Owner attestation and expiry for the case's authorization to act."""

    owner_attestation_required: bool = True
    expires_at: AwareDatetime


class RepositoryTarget(AegisModel):
    """An in-scope repository, pinned to an exact commit."""

    id: _Id
    commit: Annotated[str, StringConstraints(min_length=1, max_length=200)]


class ServiceTarget(AegisModel):
    """An in-scope service, bound to a case-specific network."""

    id: _Id
    network: Annotated[str, StringConstraints(min_length=1, max_length=200)]


class Targets(AegisModel):
    """The explicit, enumerable set of in-scope repositories and services.

    FR-SCP-003 requires that a target which cannot be resolved to an
    explicit scope object is rejected; an empty ``Targets`` would mean
    nothing is in scope, so at least one target must be declared.
    """

    repositories: tuple[RepositoryTarget, ...] = ()
    services: tuple[ServiceTarget, ...] = ()

    @model_validator(mode="after")
    def _require_at_least_one_target(self) -> Targets:
        if not self.repositories and not self.services:
            raise ValueError("a scope policy must declare at least one repository or service")
        return self


class NetworkAllowRule(AegisModel):
    """A single pinned network exception to the default-deny egress rule."""

    destination: Annotated[str, StringConstraints(min_length=1, max_length=253)]
    ports: tuple[_Port, ...] = Field(min_length=1)


class NetworkPolicy(AegisModel):
    """Network policy. ``default`` is fixed to ``deny`` (SR-NET-001).

    Fixing the field to the literal ``"deny"`` makes default-deny a
    structural invariant of the schema rather than a convention that a
    scope document could opt out of.
    """

    default: Literal["deny"] = "deny"
    allow: tuple[NetworkAllowRule, ...] = ()


class FilesystemPolicy(AegisModel):
    """Filesystem access, expressed as explicit read/write URI prefixes."""

    read: tuple[Uri, ...] = ()
    write: tuple[Uri, ...] = ()


class ToolsPolicy(AegisModel):
    """The allow-list of typed tool adapters usable within this case."""

    allow: tuple[ToolId, ...] = ()


class ActionsPolicy(AegisModel):
    """Action-type disposition buckets: automatic, approval-gated, denied.

    An action type listed in more than one bucket is ambiguous about its
    own authorization tier, which docs/CONTROL_PLANE.md's authorization
    tuple treats as a denial condition ("An omitted or ambiguous field
    causes denial."); this is rejected at construction time.
    """

    auto: tuple[ActionId, ...] = ()
    approval: tuple[ActionId, ...] = ()
    deny: tuple[ActionId, ...] = ()

    @model_validator(mode="after")
    def _reject_ambiguous_action_disposition(self) -> ActionsPolicy:
        seen: dict[str, str] = {}
        for bucket_name, bucket in (
            ("auto", self.auto),
            ("approval", self.approval),
            ("deny", self.deny),
        ):
            for action_id in bucket:
                prior = seen.get(action_id)
                if prior is not None and prior != bucket_name:
                    raise ValueError(
                        f"action '{action_id}' is listed in both '{prior}' and "
                        f"'{bucket_name}': ambiguous action disposition is denied"
                    )
                seen[action_id] = bucket_name
        return self


class Budgets(AegisModel):
    """Hard resource limits for the case (docs/CONTROL_PLANE.md)."""

    tool_calls: Annotated[int, Field(gt=0)]
    model_tokens: Annotated[int, Field(gt=0)]
    wall_time_seconds: Annotated[int, Field(gt=0)]
    spend_usd: Annotated[float, Field(ge=0)]


class ScopePolicy(AegisModel):
    """The complete, versioned scope policy for one case.

    A case must never be actioned without one of these existing first
    (FR-SCP-001); ``Case.scope_ref``/``Case.scope_digest`` bind a case to
    exactly one ``ScopePolicy`` instance and version.
    """

    schema_version: Literal["aegis.scope_policy/v1"] = SCOPE_POLICY_SCHEMA_VERSION
    case_id: CaseId
    version: Annotated[int, Field(ge=1)]
    authorization: Authorization
    targets: Targets
    network: NetworkPolicy
    filesystem: FilesystemPolicy
    tools: ToolsPolicy
    actions: ActionsPolicy
    budgets: Budgets
