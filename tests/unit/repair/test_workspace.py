from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from aegis.repair.candidate import DiffPolicyError, PatchCandidate
from aegis.repair.hashing import hash_source_tree
from aegis.repair.workspace import PatchApplyError, create_patch_workspace


@pytest.fixture
def base_source(tmp_path: Path) -> Path:
    source = tmp_path / "base"
    source.mkdir()
    (source / "app.py").write_text("value = 1\n")
    return source


def test_create_patch_workspace_applies_a_valid_diff(
    base_source: Path, make_candidate: Callable[..., PatchCandidate]
) -> None:
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-value = 1\n+value = 2\n"
    candidate = make_candidate(diff=diff, base_source_digest=hash_source_tree(base_source))
    workspace = create_patch_workspace(
        str(base_source), candidate, allowed_files=frozenset({"app.py"})
    )
    assert (workspace / "app.py").read_text() == "value = 2\n"


def test_create_patch_workspace_leaves_the_base_source_untouched(
    base_source: Path, make_candidate: Callable[..., PatchCandidate]
) -> None:
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-value = 1\n+value = 2\n"
    candidate = make_candidate(diff=diff, base_source_digest=hash_source_tree(base_source))
    create_patch_workspace(str(base_source), candidate, allowed_files=frozenset({"app.py"}))
    assert (base_source / "app.py").read_text() == "value = 1\n"


def test_create_patch_workspace_rejects_out_of_policy_diff_before_copying(
    base_source: Path, make_candidate: Callable[..., PatchCandidate]
) -> None:
    diff = "--- a/other.py\n+++ b/other.py\n@@ -1 +1 @@\n-value = 1\n+value = 2\n"
    candidate = make_candidate(diff=diff, files_changed=("other.py",))
    with pytest.raises(DiffPolicyError):
        create_patch_workspace(str(base_source), candidate, allowed_files=frozenset({"app.py"}))


def test_create_patch_workspace_raises_when_diff_does_not_apply(
    base_source: Path, make_candidate: Callable[..., PatchCandidate]
) -> None:
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-value = 999\n+value = 2\n"
    candidate = make_candidate(diff=diff, base_source_digest=hash_source_tree(base_source))
    with pytest.raises(PatchApplyError):
        create_patch_workspace(str(base_source), candidate, allowed_files=frozenset({"app.py"}))
