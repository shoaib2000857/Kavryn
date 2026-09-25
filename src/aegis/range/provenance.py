"""Deployment provenance: tying a running range container to pinned source.

See docs/PRODUCT_REQUIREMENTS.md FR-VUL-004 ("Link runtime evidence to
repository, commit, artifact, file, function... where provenance
permits"). ``source_commit_digest`` reuses
``aegis.repair.hashing.hash_source_tree`` so a running deployment's
provenance and a patch candidate's claimed base are computed the same
way and are directly comparable.
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import Field

from aegis.domain.base import AegisModel, AwareDatetime, CaseId, Digest

__all__ = ["DEPLOYMENT_PROVENANCE_SCHEMA_VERSION", "DeploymentProvenance"]

DEPLOYMENT_PROVENANCE_SCHEMA_VERSION: Final[Literal["aegis.deployment_provenance/v1"]] = (
    "aegis.deployment_provenance/v1"
)


class DeploymentProvenance(AegisModel):
    schema_version: Literal["aegis.deployment_provenance/v1"] = DEPLOYMENT_PROVENANCE_SCHEMA_VERSION
    case_id: CaseId
    container_name: str = Field(min_length=1)
    image_digest: str = Field(min_length=1)
    source_repository: str = Field(min_length=1)
    source_commit_digest: Digest
    deployed_at: AwareDatetime
