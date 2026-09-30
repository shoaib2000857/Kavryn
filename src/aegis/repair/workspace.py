"""The disposable patch workspace.

See docs/TOOLS_AND_SANDBOXES.md "Patch worker": "writable disposable
repository copy; no hidden tests, evaluator ground truth, deployment
credentials, or audit access; patch application through a
library/adapter, not arbitrary host commands." This copies only the
base source directory the caller passes in — the fixture's
``hidden_tests/``/``public_tests/`` directories are physical siblings
of ``src/``, never nested inside it, so there is nothing to
accidentally include even if this function were called carelessly.

Diff application uses the system ``patch`` utility via argument array
only (ADR-006) — never a shell string built from the diff content.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

from aegis.repair.candidate import PatchCandidate, validate_diff_policy
from aegis.repair.hashing import hash_source_tree

__all__ = ["PatchApplyError", "create_patch_workspace"]


class PatchApplyError(RuntimeError):
    """Raised when the diff does not apply cleanly to the base source."""


def create_patch_workspace(
    base_source_dir: str, candidate: PatchCandidate, *, allowed_files: frozenset[str]
) -> Path:
    """Copy ``base_source_dir`` into a fresh temp dir and apply the candidate diff.

    Raises ``DiffPolicyError`` (before touching the filesystem) if the
    diff is out of policy, and ``PatchApplyError`` if it does not apply
    cleanly. The caller is responsible for deleting the returned
    directory when done (it is not a context manager: callers may need
    to inspect it after an assertion failure).
    """
    validate_diff_policy(candidate.diff, allowed_files=allowed_files)
    if hashlib.sha256(candidate.diff.encode()).hexdigest() != candidate.diff_digest.digest:
        raise PatchApplyError("candidate diff digest mismatch")
    if hash_source_tree(base_source_dir) != candidate.base_source_digest:
        raise PatchApplyError("trusted base source digest mismatch")

    workspace = Path(tempfile.mkdtemp(prefix="aegis-patch-"))
    try:
        shutil.copytree(base_source_dir, workspace, dirs_exist_ok=True, symlinks=True)
        # Recheck the snapshot before application; never follow copied links.
        if hash_source_tree(workspace) != candidate.base_source_digest:
            raise PatchApplyError("source changed while preparing the disposable snapshot")
        result = subprocess.run(
            [
                "patch",
                "--strip=1",
                "--forward",
                "--batch",
                "--fuzz=0",
                "--reject-file=-",
                "--no-backup-if-mismatch",
            ],
            cwd=workspace,
            input=candidate.diff,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            raise PatchApplyError("patch failed to apply exactly to the trusted snapshot")
    except BaseException:
        shutil.rmtree(workspace)
        raise
    return workspace
