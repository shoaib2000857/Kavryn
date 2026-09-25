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
    hasher = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        relative = path.relative_to(root).as_posix()
        hasher.update(relative.encode())
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return Digest(digest=hasher.hexdigest())
