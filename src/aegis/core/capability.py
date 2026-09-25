"""Bound, expiring capabilities with an in-memory revocation/use ledger.

The authority is process-local and is not a cryptographic or cross-process
security boundary. It provides enforceable semantics for the current
single-process runtime; signed remote capabilities remain future work.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from threading import RLock
from typing import Annotated, Final, Literal

from pydantic import Field, model_validator

from aegis.domain.action import ActionRequest
from aegis.domain.base import (
    ActionId,
    ActorId,
    AegisModel,
    AwareDatetime,
    CaseId,
    Digest,
    RecordId,
    ToolId,
    Uri,
)
from aegis.domain.policy import RiskTier

__all__ = [
    "CAPABILITY_SCHEMA_VERSION",
    "Capability",
    "CapabilityAuthority",
    "CapabilityDeniedError",
    "capability_parameters_digest",
]

CAPABILITY_SCHEMA_VERSION: Final[Literal["aegis.capability/v1"]] = "aegis.capability/v1"


class Capability(AegisModel):
    """A narrowly bound authorization grant for one transaction/action."""

    schema_version: Literal["aegis.capability/v1"] = CAPABILITY_SCHEMA_VERSION
    id: RecordId
    issuer: ActorId
    subject: ActorId
    case_id: CaseId
    transaction_id: RecordId
    scope_digest: Digest
    action_type: ActionId
    adapter: ToolId
    target_ref: Uri
    risk_tier: RiskTier
    parameters_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    single_use: bool = True
    max_uses: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def _capability_invariants(self) -> Capability:
        if self.expires_at <= self.issued_at:
            raise ValueError("capability expiry must be after issuance")
        if self.single_use and self.max_uses != 1:
            raise ValueError("single-use capabilities must have max_uses=1")
        return self


class CapabilityDeniedError(PermissionError):
    """Raised when a capability is missing, expired, revoked, or mismatched."""


class _CapabilityState:
    def __init__(self, capability: Capability) -> None:
        self.capability = capability
        self.use_count = 0
        self.revoked_at: datetime | None = None


def capability_parameters_digest(parameters: dict[str, object]) -> str:
    canonical = json.dumps(parameters, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class CapabilityAuthority:
    """Thread-safe issuer/validator/revoker for process-local capabilities."""

    def __init__(self) -> None:
        self._states: dict[str, _CapabilityState] = {}
        self._lock = RLock()

    def issue(self, capability: Capability) -> Capability:
        with self._lock:
            if capability.id in self._states:
                raise CapabilityDeniedError("capability id has already been issued")
            self._states[capability.id] = _CapabilityState(capability)
            return capability

    def consume(
        self,
        capability_id: str,
        request: ActionRequest,
        *,
        transaction_id: str,
        now: datetime,
    ) -> Capability:
        with self._lock:
            state = self._states.get(capability_id)
            if state is None:
                raise CapabilityDeniedError("unknown capability")
            grant = state.capability
            if state.revoked_at is not None:
                raise CapabilityDeniedError("capability has been revoked")
            if now < grant.issued_at or now >= grant.expires_at:
                raise CapabilityDeniedError("capability is not currently valid")
            if (
                request.case_id != grant.case_id
                or request.actor_id != grant.subject
                or transaction_id != grant.transaction_id
                or request.action_type != grant.action_type
                or request.adapter != grant.adapter
                or request.target_ref != grant.target_ref
                or capability_parameters_digest(request.parameters) != grant.parameters_digest
            ):
                raise CapabilityDeniedError("request does not match capability bindings")
            if state.use_count >= grant.max_uses:
                raise CapabilityDeniedError("capability use limit has been exhausted")
            state.use_count += 1
            return grant

    def revoke(self, capability_id: str, *, at: datetime) -> None:
        with self._lock:
            state = self._states.get(capability_id)
            if state is None:
                raise CapabilityDeniedError("unknown capability")
            if at < state.capability.issued_at:
                raise CapabilityDeniedError("revocation timestamp precedes capability issuance")
            state.revoked_at = at

    def is_revoked(self, capability_id: str) -> bool:
        with self._lock:
            state = self._states.get(capability_id)
            return state is None or state.revoked_at is not None
