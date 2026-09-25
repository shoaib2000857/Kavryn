"""Fail-closed dispatch from a ``schema_version`` string to its model.

docs/AGENTS.md requires failing closed on "unknown schema versions".
``parse_record`` is the one place that decision is made: an unrecognized
or missing ``schema_version`` is rejected before any field-level
validation runs, so a malformed or forged envelope cannot masquerade as
a newer or older record shape.
"""

from __future__ import annotations

from typing import Any, Final

from pydantic import BaseModel

from aegis.domain.action import ACTION_REQUEST_SCHEMA_VERSION, ActionRequest
from aegis.domain.audit import AUDIT_EVENT_SCHEMA_VERSION, AuditEvent
from aegis.domain.case import CASE_SCHEMA_VERSION, Case
from aegis.domain.evidence import EVIDENCE_ENVELOPE_SCHEMA_VERSION, EvidenceEnvelope
from aegis.domain.policy import POLICY_DECISION_SCHEMA_VERSION, PolicyDecision
from aegis.domain.scope import SCOPE_POLICY_SCHEMA_VERSION, ScopePolicy

__all__ = ["SCHEMA_REGISTRY", "UnknownSchemaVersionError", "parse_record"]

SCHEMA_REGISTRY: Final[dict[str, type[BaseModel]]] = {
    CASE_SCHEMA_VERSION: Case,
    SCOPE_POLICY_SCHEMA_VERSION: ScopePolicy,
    EVIDENCE_ENVELOPE_SCHEMA_VERSION: EvidenceEnvelope,
    ACTION_REQUEST_SCHEMA_VERSION: ActionRequest,
    POLICY_DECISION_SCHEMA_VERSION: PolicyDecision,
    AUDIT_EVENT_SCHEMA_VERSION: AuditEvent,
}


class UnknownSchemaVersionError(ValueError):
    """Raised when a record's ``schema_version`` is missing or unrecognized."""


def parse_record(data: dict[str, Any]) -> BaseModel:
    """Parse ``data`` into its typed model, chosen by ``schema_version``.

    Fails closed: a missing, non-string, or unregistered ``schema_version``
    raises ``UnknownSchemaVersionError`` rather than guessing a model or
    falling back to a permissive shape.
    """
    schema_version = data.get("schema_version")
    if not isinstance(schema_version, str) or schema_version not in SCHEMA_REGISTRY:
        raise UnknownSchemaVersionError(f"unknown or missing schema_version: {schema_version!r}")
    model = SCHEMA_REGISTRY[schema_version]
    return model.model_validate(data)
