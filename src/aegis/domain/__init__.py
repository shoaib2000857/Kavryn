"""Typed domain schemas for Aegis Defender (Change 1: foundation and schemas).

Every model here is immutable (frozen) and rejects unrecognized fields.
See docs/EVIDENCE_AND_ASSURANCE.md and docs/CONTROL_PLANE.md for the
conceptual schemas this module implements.
"""

from aegis.domain.action import ActionRequest
from aegis.domain.audit import AuditEvent, AuditEventType
from aegis.domain.base import (
    ActorRole,
    Digest,
    Producer,
    ProducerType,
)
from aegis.domain.case import Case, CaseStatus
from aegis.domain.evidence import Classification, EvidenceEnvelope
from aegis.domain.policy import PolicyDecision, PolicyOutcome, RiskTier
from aegis.domain.registry import SCHEMA_REGISTRY, UnknownSchemaVersionError, parse_record
from aegis.domain.scope import (
    ActionsPolicy,
    Authorization,
    Budgets,
    FilesystemPolicy,
    NetworkAllowRule,
    NetworkPolicy,
    RepositoryTarget,
    ScopePolicy,
    ServiceTarget,
    Targets,
    ToolsPolicy,
)

__all__ = [
    "SCHEMA_REGISTRY",
    "ActionRequest",
    "ActionsPolicy",
    "ActorRole",
    "AuditEvent",
    "AuditEventType",
    "Authorization",
    "Budgets",
    "Case",
    "CaseStatus",
    "Classification",
    "Digest",
    "EvidenceEnvelope",
    "FilesystemPolicy",
    "NetworkAllowRule",
    "NetworkPolicy",
    "PolicyDecision",
    "PolicyOutcome",
    "Producer",
    "ProducerType",
    "RepositoryTarget",
    "RiskTier",
    "ScopePolicy",
    "ServiceTarget",
    "Targets",
    "ToolsPolicy",
    "UnknownSchemaVersionError",
    "parse_record",
]
