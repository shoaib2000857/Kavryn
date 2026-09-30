"""Deterministic content hashing for a source tree.

Used on both sides of the repair loop: whoever prepares a
``PatchCandidate`` records the base source digest it claims to have
patched against, and the clean-room verifier independently recomputes
the same digest over its own trusted, read-only copy of that source and
compares — a mismatch means the candidate's claimed base does not match
reality (docs/EVIDENCE_AND_ASSURANCE.md hard failure: "evidence digest/
signature mismatch").
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from aegis.domain.base import Digest

__all__ = ["hash_source_tree"]


def hash_source_tree(root: str | Path) -> Digest:
    """Hash every file under ``root`` by sorted relative path and content.

    Deterministic regardless of filesystem iteration order; sensitive to
    any file addition, removal, rename, or content change.
    """
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("source root must be a non-symlink directory")
    hasher = hashlib.sha256()
    paths = sorted(root.rglob("*"))
    if any(p.is_symlink() or not (p.is_file() or p.is_dir()) for p in paths):
        raise ValueError("source tree contains symlinks or special files")
    for path in (p for p in paths if p.is_file()):
        relative = path.relative_to(root).as_posix()
        hasher.update(relative.encode())
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return Digest(digest=hasher.hexdigest())
