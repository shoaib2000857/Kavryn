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

import shutil
import subprocess
import tempfile
from pathlib import Path

from aegis.repair.candidate import PatchCandidate, validate_diff_policy

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

    workspace = Path(tempfile.mkdtemp(prefix="aegis-patch-"))
    shutil.copytree(base_source_dir, workspace, dirs_exist_ok=True)

    diff_path = workspace / ".aegis-candidate.diff"
    diff_path.write_text(candidate.diff)
    try:
        result = subprocess.run(
            ["patch", "--strip=1", "--forward", "--input", str(diff_path)],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        diff_path.unlink(missing_ok=True)

    if result.returncode != 0:
        raise PatchApplyError(f"patch failed to apply:\n{result.stdout}\n{result.stderr}")
    return workspace
