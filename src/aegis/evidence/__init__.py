"""In-memory artifact and audit interfaces (docs/IMPLEMENTATION_HANDOFF.md Change 2)."""

from aegis.evidence.audit import AuditChainError, AuditSink, InMemoryAuditSink
from aegis.evidence.store import ArtifactNotFoundError, ArtifactStore, InMemoryArtifactStore

__all__ = [
    "ArtifactNotFoundError",
    "ArtifactStore",
    "AuditChainError",
    "AuditSink",
    "InMemoryArtifactStore",
    "InMemoryAuditSink",
]
