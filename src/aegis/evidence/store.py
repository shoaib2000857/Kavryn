"""A content-addressed artifact store.

See docs/EVIDENCE_AND_ASSURANCE.md ("content-address every artifact")
and docs/ARCHITECTURE.md's "Evidence store" row. This in-memory
implementation is the Change 2 deliverable; a durable/object-storage
backend is deferred (docs/OPEN_QUESTIONS.md OQ-007) but must satisfy
the same ``ArtifactStore`` protocol.
"""

from __future__ import annotations

import hashlib
from typing import Protocol

from aegis.domain.base import Digest

__all__ = ["ArtifactNotFoundError", "ArtifactStore", "InMemoryArtifactStore", "sha256_digest"]


def sha256_digest(content: bytes) -> Digest:
    return Digest(digest=hashlib.sha256(content).hexdigest())


class ArtifactNotFoundError(KeyError):
    """Raised when a lookup digest has no corresponding stored content."""


class ArtifactStore(Protocol):
    def put(self, content: bytes) -> Digest:
        """Store ``content`` and return its content digest."""

    def get(self, digest: Digest) -> bytes:
        """Return the content addressed by ``digest``, or raise if absent."""

    def __contains__(self, digest: Digest) -> bool: ...


class InMemoryArtifactStore:
    """A process-local, content-addressed artifact store.

    Content is immutable once stored: writing under a digest that
    already exists is a no-op (the content is identical by definition
    of content addressing), never an overwrite.
    """

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    def put(self, content: bytes) -> Digest:
        digest = sha256_digest(content)
        self._objects.setdefault(digest.digest, content)
        return digest

    def get(self, digest: Digest) -> bytes:
        try:
            return self._objects[digest.digest]
        except KeyError:
            raise ArtifactNotFoundError(digest.digest) from None

    def __contains__(self, digest: Digest) -> bool:
        return digest.digest in self._objects
