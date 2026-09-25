from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from aegis.domain.base import ActorRole, AegisModel, Digest, Producer, ProducerType


class _Example(AegisModel):
    value: int


def test_aegis_model_is_frozen() -> None:
    example = _Example(value=1)
    with pytest.raises(ValidationError):
        example.value = 2  # type: ignore[misc]


def test_aegis_model_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        _Example(value=1, extra_field="not allowed")  # type: ignore[call-arg]


def test_digest_accepts_valid_sha256() -> None:
    digest = Digest(digest="f" * 64)
    assert digest.algorithm == "sha256"


@pytest.mark.parametrize(
    "value",
    [
        "too-short",
        "g" * 64,  # not hex
        "A" * 64,  # uppercase not accepted
        "a" * 63,  # too short
        "a" * 65,  # too long
    ],
)
def test_digest_rejects_malformed_hash(value: str) -> None:
    with pytest.raises(ValidationError):
        Digest(digest=value)


def test_digest_rejects_non_sha256_algorithm() -> None:
    with pytest.raises(ValidationError):
        Digest(algorithm="md5", digest="a" * 64)


def test_producer_requires_all_fields() -> None:
    producer = Producer(type=ProducerType.ADAPTER, name="semgrep", version="1.90.0")
    assert producer.type is ProducerType.ADAPTER


def test_actor_role_is_closed_vocabulary() -> None:
    with pytest.raises(ValueError):
        ActorRole("attacker")


def test_aware_datetime_rejects_naive_timestamp() -> None:
    from aegis.domain.case import Case

    naive = datetime(2026, 9, 3, 12, 0, 0)  # no tzinfo
    with pytest.raises(ValidationError):
        Case(
            id="AGE-0001",
            title="x",
            created_at=naive,
            created_by="operator:alice",
            scope_ref="scope://AGE-0001/1",
            scope_digest=Digest(digest="a" * 64),
        )
