from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from aegis.domain.base import Digest
from aegis.providers.hosted import HostedProviderConfig
from aegis.repair.candidate import DiffPolicyError, PatchCandidate, validate_diff_policy
from aegis.repair.hashing import hash_source_tree
from aegis.repair.provider import HostedPatchProvider, PatchGenerationError, PatchGenerationRequest
from aegis.repair.source import SourceSpan, canonical_source_diff
from aegis.repair.workspace import PatchApplyError, create_patch_workspace


@pytest.mark.parametrize("prefix", ["old mode 100644\nnew mode 100755\n", "GIT binary patch\n"])
def test_patch_policy_rejects_effectful_metadata(prefix: str) -> None:
    diff = prefix + canonical_source_diff("app.py", "old\n", "new\n")
    with pytest.raises(DiffPolicyError, match="unsupported"):
        validate_diff_policy(diff, allowed_files=frozenset({"app.py"}))


def test_patch_policy_rejects_hidden_old_path_and_duplicate_sections() -> None:
    diff = canonical_source_diff("app.py", "old\n", "new\n")
    with pytest.raises(DiffPolicyError, match="source and destination"):
        validate_diff_policy(
            diff.replace("--- a/app.py", "--- a/../../outside"), allowed_files=frozenset({"app.py"})
        )
    with pytest.raises(DiffPolicyError, match="duplicate"):
        validate_diff_policy(diff + diff, allowed_files=frozenset({"app.py"}))


def test_workspace_rejects_fuzzy_context_and_cleans_failed_snapshot(
    tmp_path: Path, make_candidate: Callable[..., PatchCandidate], monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text("actual header\nvalue = 1\nactual footer\n")
    patch = canonical_source_diff(
        "app.py",
        "stale header\nvalue = 1\nstale footer\n",
        "stale header\nvalue = 2\nstale footer\n",
    )
    candidate = make_candidate(diff=patch, base_source_digest=hash_source_tree(root))
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr("aegis.repair.workspace.tempfile.mkdtemp", lambda **kwargs: str(scratch))
    with pytest.raises(PatchApplyError, match="exactly"):
        create_patch_workspace(str(root), candidate, allowed_files=frozenset({"app.py"}))
    assert not scratch.exists()
    assert (root / "app.py").read_text() == "actual header\nvalue = 1\nactual footer\n"


def test_patch_transport_does_not_clobber_source_named_like_internal_diff(
    tmp_path: Path, make_candidate: Callable[..., PatchCandidate]
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n")
    (root / ".aegis-candidate.diff").write_text("trusted unrelated content\n")
    candidate = make_candidate(
        diff=canonical_source_diff("app.py", "value = 1\n", "value = 2\n"),
        base_source_digest=hash_source_tree(root),
    )
    workspace = create_patch_workspace(str(root), candidate, allowed_files=frozenset({"app.py"}))
    try:
        assert (workspace / ".aegis-candidate.diff").read_text() == "trusted unrelated content\n"
    finally:
        shutil.rmtree(workspace)


@pytest.mark.parametrize("final_newline", [True, False])
def test_canonical_diff_applies_exactly_with_and_without_final_newline(
    tmp_path: Path, make_candidate: Callable[..., PatchCandidate], final_newline: bool
) -> None:
    original = "value = 1" + ("\n" if final_newline else "")
    updated = "value = 2" + ("\n" if final_newline else "")
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text(original)
    candidate = make_candidate(
        diff=canonical_source_diff("app.py", original, updated),
        base_source_digest=hash_source_tree(root),
    )
    workspace = create_patch_workspace(str(root), candidate, allowed_files=frozenset({"app.py"}))
    try:
        assert (workspace / "app.py").read_text() == updated
        assert (root / "app.py").read_text() == original
    finally:
        shutil.rmtree(workspace)


def test_localized_replacement_preserves_unexposed_prefix_suffix_and_applies(
    tmp_path: Path,
) -> None:
    prefix = "PRIVATE_OUTSIDE_CONTEXT = 'not for inference'\n\n"
    fragment = "class Local:\n    value = 1\n"
    suffix = "\nclass Other:\n    value = 77\n"
    source = prefix + fragment + suffix
    replacement = "class Local:\n    value = 2\n\n"
    captured: list[dict[str, object]] = []

    def post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> bytes:
        payload = json.loads(body)
        captured.append(json.loads(payload["messages"][1]["content"]))
        return json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "updated_source": replacement,
                                    "root_cause": "incorrect value",
                                    "repair_invariant": "preserve all other classes",
                                }
                            )
                        }
                    }
                ]
            }
        ).encode()

    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text(source)
    provider = HostedPatchProvider(
        HostedProviderConfig(base_url="https://offline.example/v1", model="replay"),
        api_key="test",
        http_post=post,
        public_syntax_retry=True,
    )
    request = PatchGenerationRequest(
        case_id="AGE-SPAN-01",
        base_repository="owned-test",
        base_source_digest=hash_source_tree(root),
        source_file="app.py",
        source=source,
        source_span=SourceSpan(start_line=3, end_line=4),
        vulnerability_summary="Repair the localized class.",
        allowed_files=frozenset({"app.py"}),
    )
    candidate = provider.generate(request)
    assert captured[0]["source_is_untrusted_data"] == fragment
    assert "PRIVATE_OUTSIDE_CONTEXT" not in json.dumps(captured)
    workspace = create_patch_workspace(str(root), candidate, allowed_files=frozenset({"app.py"}))
    try:
        assert (workspace / "app.py").read_text() == prefix + replacement + suffix
    finally:
        shutil.rmtree(workspace)


def test_invalid_source_span_fails_before_provider_call() -> None:
    def never_post(*args, **kwargs):
        raise AssertionError("invalid context must not reach the model")

    provider = HostedPatchProvider(
        HostedProviderConfig(base_url="https://offline.example", model="stub"),
        api_key="test",
        http_post=never_post,
    )
    request = PatchGenerationRequest(
        case_id="AGE-SPAN-01",
        base_repository="owned-test",
        base_source_digest=Digest(digest="a" * 64),
        source_file="app.py",
        source="x = 1\n",
        source_span=SourceSpan(start_line=1, end_line=9),
        vulnerability_summary="repair",
        allowed_files=frozenset({"app.py"}),
    )
    with pytest.raises(PatchGenerationError, match="source span"):
        provider.generate(request)
    assert provider.last_request_count == 0


def test_stale_source_and_tampered_diff_are_rejected(
    tmp_path: Path, make_candidate: Callable[..., PatchCandidate]
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.py").write_text("value = 1\n")
    candidate = make_candidate(
        diff=canonical_source_diff("app.py", "value = 1\n", "value = 2\n"),
        base_source_digest=hash_source_tree(root),
    )
    tampered = candidate.model_copy(update={"diff_digest": Digest(digest="0" * 64)})
    with pytest.raises(PatchApplyError, match="diff digest"):
        create_patch_workspace(str(root), tampered, allowed_files=frozenset({"app.py"}))
    (root / "app.py").write_text("value = 3\n")
    with pytest.raises(PatchApplyError, match="base source digest"):
        create_patch_workspace(str(root), candidate, allowed_files=frozenset({"app.py"}))


def test_source_tree_symlinks_and_special_files_are_rejected(tmp_path: Path) -> None:
    import os

    root = tmp_path / "source"
    root.mkdir()
    secret = tmp_path / "private"
    secret.write_text("not source")
    (root / "app.py").symlink_to(secret)
    with pytest.raises(ValueError, match="symlinks"):
        hash_source_tree(root)
    (root / "app.py").unlink()
    os.mkfifo(root / "pipe")
    with pytest.raises(ValueError, match="special"):
        hash_source_tree(root)


@pytest.mark.parametrize("path", ["../app.py", "/app.py", "app\n.py", "a/./app.py"])
def test_canonical_diff_rejects_unsafe_source_paths(path: str) -> None:
    with pytest.raises(ValueError, match="safe relative"):
        canonical_source_diff(path, "old\n", "new\n")
