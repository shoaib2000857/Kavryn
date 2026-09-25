"""PatchCandidate: a proposed diff, typed and validated before it is trusted.

See docs/EVIDENCE_AND_ASSURANCE.md "Patch candidate schema" and
docs/PRODUCT_REQUIREMENTS.md FR-PAT-001/FR-PAT-002. Diff-policy
validation (``validate_diff_policy``) is a standalone function, not
baked into the model, because it is applied independently on both
sides of the repair loop: once by whoever prepares the disposable patch
workspace, and again by the clean-room verifier, which never trusts
that the first check actually ran (docs/DECISIONS.md ADR-009).
"""

from __future__ import annotations

from typing import Annotated, Final, Literal

from pydantic import Field, StringConstraints, model_validator

from aegis.domain.base import AegisModel, AwareDatetime, CaseId, Digest, Reason, RecordId

# A unified diff, where every byte -- including a trailing newline on
# the final content line -- is significant to `patch`/`git apply`.
# AegisModel's model-wide `str_strip_whitespace=True` would silently
# strip a trailing newline and corrupt the diff (caught by
# tests/unit/repair/test_workspace.py failing against the real `patch`
# binary); this field explicitly overrides that.
_DiffText = Annotated[str, StringConstraints(min_length=1, strip_whitespace=False)]

__all__ = ["DiffPolicyError", "PatchCandidate", "changed_files", "validate_diff_policy"]

PATCH_CANDIDATE_SCHEMA_VERSION: Final[Literal["aegis.patch_candidate/v1"]] = (
    "aegis.patch_candidate/v1"
)

_DEFAULT_FORBIDDEN_FRAGMENTS: Final[frozenset[str]] = frozenset(
    {"test", "hidden_tests", "public_tests", "verifier", "policy", "audit", "aegis"}
)


class DiffPolicyError(ValueError):
    """Raised when a diff touches a file or scope it must not."""


def changed_files(diff: str) -> tuple[str, ...]:
    """Extract target file paths from a unified diff's ``+++ b/...`` headers."""
    files = []
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:].split("\t")[0].strip()
            if path.startswith("b/"):
                path = path[2:]
            files.append(path)
    return tuple(files)


def validate_diff_policy(
    diff: str,
    *,
    allowed_files: frozenset[str],
    forbidden_path_fragments: frozenset[str] = _DEFAULT_FORBIDDEN_FRAGMENTS,
) -> tuple[str, ...]:
    """Return the changed files if ``diff`` satisfies scope policy, else raise.

    Fails closed on: no recognizable changed files, an absolute path, a
    ``.``/``..`` traversal segment, a path outside ``allowed_files``, or
    a path touching a forbidden fragment (tests, verifier, policy,
    audit) — docs/EVIDENCE_AND_ASSURANCE.md's "Diff policy" hard
    failure: "No forbidden files, test deletion, policy edits, or
    excessive unrelated changes."
    """
    files = changed_files(diff)
    if not files:
        raise DiffPolicyError("diff touches no recognizable files")
    for path in files:
        if path.startswith("/") or ".." in path.split("/"):
            raise DiffPolicyError(f"diff touches an unsafe path: '{path}'")
        if path not in allowed_files:
            raise DiffPolicyError(f"diff touches a file outside the allowed set: '{path}'")
        lowered = path.lower()
        if any(fragment in lowered for fragment in forbidden_path_fragments):
            raise DiffPolicyError(f"diff touches a forbidden path fragment: '{path}'")
    return files


class PatchCandidate(AegisModel):
    """A proposed fix: a diff plus the provenance needed to verify it independently."""

    schema_version: Literal["aegis.patch_candidate/v1"] = PATCH_CANDIDATE_SCHEMA_VERSION
    id: RecordId
    case_id: CaseId
    base_repository: str = Field(min_length=1, max_length=200)
    base_source_digest: Digest
    diff: _DiffText
    diff_digest: Digest
    files_changed: tuple[str, ...]
    root_cause: Reason
    repair_invariant: Reason
    generated_at: AwareDatetime

    @model_validator(mode="after")
    def _files_changed_matches_diff(self) -> PatchCandidate:
        actual = set(changed_files(self.diff))
        if actual != set(self.files_changed):
            raise ValueError(
                "files_changed does not match the files the diff actually touches: "
                f"declared={sorted(self.files_changed)} actual={sorted(actual)}"
            )
        return self
