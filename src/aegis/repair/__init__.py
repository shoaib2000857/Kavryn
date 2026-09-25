"""Patch candidate handling and the disposable patch workspace.

See docs/IMPLEMENTATION_HANDOFF.md Change 6. This package never imports
from ``aegis.verifier`` — the hidden-test side of the repair loop — and
the reverse is also true, so the physical/logical separation
docs/DECISIONS.md ADR-009 requires is enforced by the module boundary
itself, not only by convention.
"""

from aegis.repair.candidate import (
    DiffPolicyError,
    PatchCandidate,
    changed_files,
    validate_diff_policy,
)
from aegis.repair.hashing import hash_source_tree
from aegis.repair.workspace import PatchApplyError, create_patch_workspace

__all__ = [
    "DiffPolicyError",
    "PatchApplyError",
    "PatchCandidate",
    "changed_files",
    "create_patch_workspace",
    "hash_source_tree",
    "validate_diff_policy",
]
