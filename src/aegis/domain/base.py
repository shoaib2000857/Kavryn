"""Shared value objects and base model for the Aegis domain schemas.

These types encode invariants from ``docs/CONTROL_PLANE.md`` and
``docs/EVIDENCE_AND_ASSURANCE.md`` directly in the type system so that
malformed identifiers, targets, or digests are rejected at construction
time rather than trusted downstream (fail closed on ambiguous input).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, StringConstraints

__all__ = [
    "ActionId",
    "ActorId",
    "ActorRole",
    "AegisModel",
    "AwareDatetime",
    "CaseId",
    "Digest",
    "Producer",
    "ProducerType",
    "Reason",
    "RecordId",
    "ToolId",
    "Uri",
]


class AegisModel(BaseModel):
    """Base class for every Aegis domain record.

    Frozen and extra-forbidding: records are immutable once constructed
    and unrecognized fields are rejected rather than silently ignored,
    per the fail-closed posture required by ``AGENTS.md``.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )


# A short, opaque case identifier. Examples in the docs use "AGE-0001";
# this pattern is intentionally looser than that convention since the
# final case-ID scheme is an implementation detail, not an accepted
# decision (see docs/OPEN_QUESTIONS.md).
CaseId = Annotated[
    str,
    StringConstraints(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]

# A generic record identifier for entities defined in this change
# (evidence envelopes, action requests, policy decisions, audit events).
RecordId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]

# An actor identifier, e.g. "operator:alice", "reasoning_runtime:v1".
ActorId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]

# A resource reference in URI form, e.g. "artifact://sha256/...",
# "workspace://AGE-0001/candidate-2", "asset://demo-api". Requiring an
# explicit scheme prevents free-text or ambiguous target references from
# resolving to a scope object (FR-SCP-003).
Uri = Annotated[
    str,
    StringConstraints(min_length=3, max_length=2048, pattern=r"^[a-z][a-z0-9+.-]*://\S+$"),
]

# A short non-empty rationale string. Untrusted per docs/THREAT_MODEL.md's
# prompt-injection trust rule: stored as data, never interpreted as an
# instruction, and never sufficient on its own to authorize anything.
Reason = Annotated[str, StringConstraints(min_length=1, max_length=1000)]

# A dotted "namespace.verb" identifier for an action type or tool, e.g.
# "test.run", "contain.rate_limit", "semgrep.scan" (docs/CONTROL_PLANE.md).
# The strict pattern is a deliberate control: it gives the model no way
# to smuggle a free-form command string through an action-type field.
ActionId = Annotated[
    str,
    StringConstraints(
        min_length=3, max_length=128, pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"
    ),
]
ToolId = ActionId


class ActorRole(StrEnum):
    """Who is acting, for the authorization tuple in docs/CONTROL_PLANE.md."""

    OPERATOR = "operator"
    REASONING_RUNTIME = "reasoning_runtime"
    WORKER = "worker"
    CONTROL_PLANE = "control_plane"
    SYSTEM = "system"


class ProducerType(StrEnum):
    """What kind of component produced an evidence record."""

    ADAPTER = "adapter"
    SENSOR = "sensor"
    OPERATOR = "operator"
    MODEL = "model"
    CONTROL_PLANE = "control_plane"


class Producer(AegisModel):
    """Provenance of a record: what produced it, and at what pinned version."""

    type: ProducerType
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    version: Annotated[str, StringConstraints(min_length=1, max_length=128)]


class Digest(AegisModel):
    """A content hash used to content-address an artifact or record.

    Only sha256 is accepted for this change; widening the algorithm set
    later is additive and does not require a schema version bump.
    """

    algorithm: Annotated[str, StringConstraints(pattern=r"^sha256$")] = "sha256"
    digest: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
