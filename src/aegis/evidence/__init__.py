"""Artifact/audit interfaces and their in-memory or local durable backends."""

from aegis.evidence.audit import AuditChainError, AuditSink, InMemoryAuditSink
from aegis.evidence.sqlite_store import ArtifactIntegrityError, SQLiteEvidenceStore
from aegis.evidence.store import ArtifactNotFoundError, ArtifactStore, InMemoryArtifactStore

__all__ = [
    "ArtifactIntegrityError",
    "ArtifactNotFoundError",
    "ArtifactStore",
    "AuditChainError",
    "AuditSink",
    "InMemoryArtifactStore",
    "InMemoryAuditSink",
    "SQLiteEvidenceStore",
]
