from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from aegis.repair.candidate import (
    DiffPolicyError,
    PatchCandidate,
    changed_files,
    validate_diff_policy,
)

MULTI_FILE_DIFF = """--- a/app.py
+++ b/app.py
@@ -1,1 +1,1 @@
-old
+new
--- a/other.py
+++ b/other.py
@@ -1,1 +1,1 @@
-old
+new
"""


def test_changed_files_extracts_target_paths_from_plus_plus_plus_headers() -> None:
    assert changed_files(MULTI_FILE_DIFF) == ("app.py", "other.py")


def test_validate_diff_policy_accepts_an_allowed_file() -> None:
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-x\n+y\n"
    assert validate_diff_policy(diff, allowed_files=frozenset({"app.py"})) == ("app.py",)


def test_validate_diff_policy_rejects_no_recognizable_files() -> None:
    with pytest.raises(DiffPolicyError, match="no recognizable"):
        validate_diff_policy("not a diff at all", allowed_files=frozenset({"app.py"}))


def test_validate_diff_policy_rejects_file_outside_allowed_set() -> None:
    diff = "--- a/evil.py\n+++ b/evil.py\n@@ -1 +1 @@\n-x\n+y\n"
    with pytest.raises(DiffPolicyError, match="outside the allowed set"):
        validate_diff_policy(diff, allowed_files=frozenset({"app.py"}))


@pytest.mark.parametrize(
    "path",
    ["/etc/passwd", "../../etc/passwd", "a/../../etc/passwd"],
)
def test_validate_diff_policy_rejects_unsafe_paths(path: str) -> None:
    diff = f"--- a/x\n+++ b/{path}\n@@ -1 +1 @@\n-x\n+y\n"
    with pytest.raises(DiffPolicyError, match="unsafe path"):
        validate_diff_policy(diff, allowed_files=frozenset({path}))


@pytest.mark.parametrize(
    "path", ["test_public.py", "hidden_tests/test_exploit_replay.py", "aegis_policy.py"]
)
def test_validate_diff_policy_rejects_forbidden_fragments(path: str) -> None:
    diff = f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-x\n+y\n"
    with pytest.raises(DiffPolicyError, match="forbidden path fragment"):
        validate_diff_policy(diff, allowed_files=frozenset({path}))


def test_patch_candidate_round_trips(make_candidate: Callable[..., PatchCandidate]) -> None:
    candidate = make_candidate()
    restored = PatchCandidate.model_validate_json(candidate.model_dump_json())
    assert restored == candidate


def test_patch_candidate_rejects_files_changed_mismatch(
    make_candidate: Callable[..., PatchCandidate],
) -> None:
    with pytest.raises(ValidationError, match="does not match"):
        make_candidate(files_changed=("some_other_file.py",))
