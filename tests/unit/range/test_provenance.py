from __future__ import annotations

from datetime import datetime

from aegis.domain.base import Digest
from aegis.range.provenance import DeploymentProvenance


def test_deployment_provenance_round_trips(now: datetime) -> None:
    provenance = DeploymentProvenance(
        case_id="AGE-0001",
        container_name="aegis-range-app-AGE-0001",
        image_digest="sha256:" + "a" * 64,
        source_repository="path-traversal-v1",
        source_commit_digest=Digest(digest="b" * 64),
        deployed_at=now,
    )
    restored = DeploymentProvenance.model_validate_json(provenance.model_dump_json())
    assert restored == provenance
