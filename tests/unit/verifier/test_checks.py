from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from aegis.domain.base import Digest
from aegis.repair.candidate import PatchCandidate
from aegis.repair.hashing import hash_source_tree
from aegis.tools.findings import NormalizedFinding
from aegis.verifier.checks import (
    check_clean_room_tests,
    check_diff_policy,
    check_security_rescan,
    check_source_integrity,
)
from aegis.verifier.models import CheckStatus
from aegis.workers.container import ContainerRunResult, ContainerRunSpec

PASSING_JUNIT = """<?xml version="1.0"?>
<testsuites><testsuite name="pytest">
<testcase classname="public.test_public" name="test_healthz_ok" />
<testcase classname="hidden.test_exploit_replay" name="test_blocked" />
<testcase classname="hidden.test_regression" name="test_still_works" />
</testsuite></testsuites>"""

FAILING_EXPLOIT_JUNIT = """<?xml version="1.0"?>
<testsuites><testsuite name="pytest">
<testcase classname="public.test_public" name="test_healthz_ok" />
<testcase classname="hidden.test_exploit_replay" name="test_blocked">
<failure message="sentinel leaked">traceback</failure>
</testcase>
<testcase classname="hidden.test_regression" name="test_still_works" />
</testsuite></testsuites>"""


class _FakeRunner:
    def __init__(self, result: ContainerRunResult) -> None:
        self.result = result
        self.specs: list[ContainerRunSpec] = []

    def __call__(self, spec: ContainerRunSpec) -> ContainerRunResult:
        self.specs.append(spec)
        return self.result


def _finding(rule_id: str) -> NormalizedFinding:
    return NormalizedFinding(
        tool="semgrep", rule_id=rule_id, file="app.py", line=1, severity="ERROR", message="x"
    )


def test_source_integrity_passes_when_digest_matches(
    tmp_path: Path, make_candidate: Callable[..., PatchCandidate]
) -> None:
    (tmp_path / "app.py").write_text("value = 1\n")
    digest = hash_source_tree(tmp_path)
    candidate = make_candidate(base_source_digest=digest)
    result = check_source_integrity(candidate, trusted_source_dir=str(tmp_path))
    assert result.status is CheckStatus.PASS


def test_source_integrity_fails_on_mismatch(
    tmp_path: Path, make_candidate: Callable[..., PatchCandidate]
) -> None:
    (tmp_path / "app.py").write_text("value = 1\n")
    candidate = make_candidate(base_source_digest=Digest(digest="f" * 64))
    result = check_source_integrity(candidate, trusted_source_dir=str(tmp_path))
    assert result.status is CheckStatus.FAIL
    assert result.check_id == "source_integrity"
    assert result.hard_failure is True


def test_diff_policy_check_passes_within_scope(
    make_candidate: Callable[..., PatchCandidate],
) -> None:
    candidate = make_candidate()
    result = check_diff_policy(candidate, allowed_files=frozenset({"app.py"}))
    assert result.status is CheckStatus.PASS


def test_diff_policy_check_fails_outside_scope(
    make_candidate: Callable[..., PatchCandidate],
) -> None:
    candidate = make_candidate()
    result = check_diff_policy(candidate, allowed_files=frozenset({"unrelated.py"}))
    assert result.status is CheckStatus.FAIL
    assert result.hard_failure is True


def test_security_rescan_passes_when_original_finding_is_gone() -> None:
    result = check_security_rescan((_finding("path-traversal"),), ())
    assert result.status is CheckStatus.PASS


def test_security_rescan_hard_fails_when_original_finding_persists() -> None:
    result = check_security_rescan((_finding("path-traversal"),), (_finding("path-traversal"),))
    assert result.status is CheckStatus.FAIL
    assert result.hard_failure is True


def test_security_rescan_soft_fails_on_a_brand_new_finding() -> None:
    result = check_security_rescan((_finding("path-traversal"),), (_finding("new-issue"),))
    assert result.status is CheckStatus.FAIL
    assert result.hard_failure is False


def test_clean_room_tests_all_passing_produces_three_passing_checks() -> None:
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=0, stdout=PASSING_JUNIT, stderr="", timed_out=False, duration_seconds=1.0
        )
    )
    checks = check_clean_room_tests(
        image_ref="aegis-verifier@sha256:" + "a" * 64,
        trusted_source_dir="/base",
        diff_file="/candidate/patch.diff",
        public_tests_dir="/tests/public",
        hidden_tests_dir="/tests/hidden",
        runner=fake,
    )
    assert {c.check_id: c.status for c in checks} == {
        "public": CheckStatus.PASS,
        "exploit_replay": CheckStatus.PASS,
        "regression": CheckStatus.PASS,
    }


def test_clean_room_tests_spec_uses_no_network_and_the_four_expected_mounts() -> None:
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=0, stdout=PASSING_JUNIT, stderr="", timed_out=False, duration_seconds=1.0
        )
    )
    check_clean_room_tests(
        image_ref="aegis-verifier@sha256:" + "a" * 64,
        trusted_source_dir="/base",
        diff_file="/candidate/patch.diff",
        public_tests_dir="/tests/public",
        hidden_tests_dir="/tests/hidden",
        runner=fake,
    )
    spec = fake.specs[0]
    assert spec.network == "none"
    assert len(spec.read_only_mounts) == 4


def test_clean_room_tests_exploit_replay_failure_is_a_hard_failure() -> None:
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=0,
            stdout=FAILING_EXPLOIT_JUNIT,
            stderr="",
            timed_out=False,
            duration_seconds=1.0,
        )
    )
    checks = check_clean_room_tests(
        image_ref="aegis-verifier@sha256:" + "a" * 64,
        trusted_source_dir="/base",
        diff_file="/candidate/patch.diff",
        public_tests_dir="/tests/public",
        hidden_tests_dir="/tests/hidden",
        runner=fake,
    )
    by_id = {c.check_id: c for c in checks}
    assert by_id["exploit_replay"].status is CheckStatus.FAIL
    assert by_id["exploit_replay"].hard_failure is True


def test_clean_room_tests_build_failure_sentinel_exit_code_is_a_clean_build_failure() -> None:
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=2,
            stdout="",
            stderr="patch did not apply",
            timed_out=False,
            duration_seconds=0.5,
        )
    )
    checks = check_clean_room_tests(
        image_ref="aegis-verifier@sha256:" + "a" * 64,
        trusted_source_dir="/base",
        diff_file="/candidate/patch.diff",
        public_tests_dir="/tests/public",
        hidden_tests_dir="/tests/hidden",
        runner=fake,
    )
    assert len(checks) == 1
    assert checks[0].check_id == "clean_build"
    assert checks[0].status is CheckStatus.FAIL
    assert checks[0].hard_failure is True


def test_clean_room_tests_timeout_is_an_error_not_silently_verified() -> None:
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=None, stdout="", stderr="", timed_out=True, duration_seconds=120.0
        )
    )
    checks = check_clean_room_tests(
        image_ref="aegis-verifier@sha256:" + "a" * 64,
        trusted_source_dir="/base",
        diff_file="/candidate/patch.diff",
        public_tests_dir="/tests/public",
        hidden_tests_dir="/tests/hidden",
        runner=fake,
    )
    assert len(checks) == 1
    assert checks[0].status is CheckStatus.ERROR
    assert checks[0].hard_failure is True


def test_clean_room_tests_malformed_output_is_an_error() -> None:
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=0, stdout="not xml", stderr="", timed_out=False, duration_seconds=1.0
        )
    )
    checks = check_clean_room_tests(
        image_ref="aegis-verifier@sha256:" + "a" * 64,
        trusted_source_dir="/base",
        diff_file="/candidate/patch.diff",
        public_tests_dir="/tests/public",
        hidden_tests_dir="/tests/hidden",
        runner=fake,
    )
    assert len(checks) == 1
    assert checks[0].status is CheckStatus.ERROR


def test_clean_room_tests_missing_group_is_an_error() -> None:
    """If hidden regression tests were never even collected, that must
    read as an infrastructure error, never as a silent pass."""
    only_public = """<?xml version="1.0"?>
    <testsuites><testsuite name="pytest">
    <testcase classname="public.test_public" name="test_healthz_ok" />
    </testsuite></testsuites>"""
    fake = _FakeRunner(
        ContainerRunResult(
            exit_code=0, stdout=only_public, stderr="", timed_out=False, duration_seconds=1.0
        )
    )
    checks = check_clean_room_tests(
        image_ref="aegis-verifier@sha256:" + "a" * 64,
        trusted_source_dir="/base",
        diff_file="/candidate/patch.diff",
        public_tests_dir="/tests/public",
        hidden_tests_dir="/tests/hidden",
        runner=fake,
    )
    by_id = {c.check_id: c for c in checks}
    assert by_id["exploit_replay"].status is CheckStatus.ERROR
    assert by_id["regression"].status is CheckStatus.ERROR
    assert by_id["public"].status is CheckStatus.PASS
