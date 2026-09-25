from __future__ import annotations

import pytest

from aegis.domain.base import Digest
from aegis.evidence.store import ArtifactNotFoundError, InMemoryArtifactStore, sha256_digest


def test_put_then_get_round_trips_content() -> None:
    store = InMemoryArtifactStore()
    digest = store.put(b"hello evidence")
    assert store.get(digest) == b"hello evidence"


def test_put_is_content_addressed() -> None:
    store = InMemoryArtifactStore()
    digest = store.put(b"same content")
    assert digest == sha256_digest(b"same content")


def test_putting_identical_content_twice_yields_the_same_digest() -> None:
    store = InMemoryArtifactStore()
    first = store.put(b"repeat me")
    second = store.put(b"repeat me")
    assert first == second


def test_contains_reports_presence_accurately() -> None:
    store = InMemoryArtifactStore()
    digest = store.put(b"present")
    absent_digest = sha256_digest(b"absent")
    assert digest in store
    assert absent_digest not in store


def test_get_of_unknown_digest_raises() -> None:
    store = InMemoryArtifactStore()
    unknown = Digest(digest="b" * 64)
    with pytest.raises(ArtifactNotFoundError):
        store.get(unknown)


def test_different_content_yields_different_digests() -> None:
    store = InMemoryArtifactStore()
    a = store.put(b"content a")
    b = store.put(b"content b")
    assert a != b
