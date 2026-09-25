from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from aegis.domain import Case, CaseStatus, Digest


def _case_kwargs(now: datetime) -> dict[str, object]:
    return {
        "id": "AGE-0001",
        "title": "Path traversal in demo-api",
        "created_at": now,
        "created_by": "operator:alice",
        "scope_ref": "scope://AGE-0001/1",
        "scope_digest": Digest(digest="a" * 64),
    }


def test_case_round_trips_through_json(now: datetime) -> None:
    case = Case(**_case_kwargs(now))
    restored = Case.model_validate_json(case.model_dump_json())
    assert restored == case
    assert case.status is CaseStatus.OPEN


def test_case_serializes_schema_version(now: datetime) -> None:
    case = Case(**_case_kwargs(now))
    assert case.model_dump(mode="json")["schema_version"] == "aegis.case/v1"


@pytest.mark.parametrize("bad_id", ["", "-leading-dash", "AG E", "a" * 65])
def test_case_rejects_malformed_id(now: datetime, bad_id: str) -> None:
    kwargs = _case_kwargs(now)
    kwargs["id"] = bad_id
    with pytest.raises(ValidationError):
        Case(**kwargs)


def test_case_rejects_scope_ref_without_uri_scheme(now: datetime) -> None:
    kwargs = _case_kwargs(now)
    kwargs["scope_ref"] = "AGE-0001/1"  # not a URI
    with pytest.raises(ValidationError):
        Case(**kwargs)


def test_case_rejects_empty_title(now: datetime) -> None:
    kwargs = _case_kwargs(now)
    kwargs["title"] = ""
    with pytest.raises(ValidationError):
        Case(**kwargs)
