"""Run the owned IDOR fixture only in a constrained, network-disabled container."""

from __future__ import annotations

import difflib
import hashlib
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.domain.base import Digest
from aegis.repair.candidate import PatchCandidate, changed_files
from aegis.repair.hashing import hash_source_tree
from aegis.verifier.checks import check_clean_room_tests, check_diff_policy, check_source_integrity
from aegis.verifier.gate import evaluate_assurance
from aegis.verifier.models import AssuranceOutcome, CheckResult

pytestmark = pytest.mark.integration

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPOSITORY_ROOT / "ranges" / "object-authorization-v1"
IMAGE = "aegis-object-authorization-fixture:integration"
VERIFIER_IMAGE = "aegis-verifier:object-authorization-integration"
SOURCE_DIR = FIXTURE / "src"
PUBLIC_TESTS = FIXTURE / "public_tests"
HIDDEN_TESTS = FIXTURE / "hidden_tests"


def _build_verifier_image() -> str:
    dockerfile_dir = REPOSITORY_ROOT / "docker" / "verifier"
    subprocess.run(
        [
            "docker",
            "build",
            "--tag",
            VERIFIER_IMAGE,
            "--file",
            str(dockerfile_dir / "Dockerfile"),
            str(dockerfile_dir),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=600,
    )
    result = subprocess.run(
        ["docker", "inspect", VERIFIER_IMAGE, "--format={{.Id}}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


def _diff(updated_source: str) -> str:
    original = (SOURCE_DIR / "app.py").read_text(encoding="utf-8").splitlines(keepends=True)
    updated = updated_source.splitlines(keepends=True)
    return "".join(difflib.unified_diff(original, updated, fromfile="a/app.py", tofile="b/app.py"))


def _candidate(diff: str) -> PatchCandidate:
    return PatchCandidate(
        id="object-authorization-integration-candidate",
        case_id="AGE-OBJECT-AUTH-01",
        base_repository="object-authorization-v1",
        base_source_digest=hash_source_tree(str(SOURCE_DIR)),
        diff=diff,
        diff_digest=Digest(digest=hashlib.sha256(diff.encode()).hexdigest()),
        files_changed=changed_files(diff),
        root_cause="The service returns a document without checking its owner.",
        repair_invariant="Only the authenticated document owner can read that document.",
        generated_at=datetime.now(UTC),
    )


def _verify(
    candidate: PatchCandidate, image_ref: str
) -> tuple[AssuranceOutcome, tuple[CheckResult, ...]]:
    checks = [
        check_source_integrity(candidate, trusted_source_dir=str(SOURCE_DIR)),
        check_diff_policy(candidate, allowed_files=frozenset({"app.py"})),
    ]
    with tempfile.TemporaryDirectory(prefix="aegis-object-auth-verify-") as temp_dir:
        diff_file = Path(temp_dir) / "candidate.diff"
        diff_file.write_text(candidate.diff, encoding="utf-8")
        checks.extend(
            check_clean_room_tests(
                image_ref=image_ref,
                trusted_source_dir=str(SOURCE_DIR),
                diff_file=str(diff_file),
                public_tests_dir=str(PUBLIC_TESTS),
                hidden_tests_dir=str(HIDDEN_TESTS),
            )
        )
    return evaluate_assurance(tuple(checks)), tuple(checks)


def test_owned_fixture_reproduces_cross_owner_access_in_isolated_container(
    docker_available: bool,
) -> None:
    if not docker_available:
        pytest.skip("Docker is not available")

    subprocess.run(
        [
            "docker",
            "build",
            "--tag",
            IMAGE,
            "--file",
            str(FIXTURE / "Dockerfile"),
            str(FIXTURE),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=600,
    )
    check = (
        "from app import app; c=app.test_client(); "
        "a=c.get('/documents/doc-alice',headers={'Authorization':'Bearer test-token-alice'}); "
        "b=c.get('/documents/doc-alice',headers={'Authorization':'Bearer test-token-bob'}); "
        "u=c.get('/documents/doc-alice'); "
        "assert a.status_code == 200 and a.json['owner'] == 'alice'; "
        "assert b.status_code == 200 and b.json['owner'] == 'alice'; "
        "assert u.status_code == 401"
    )
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "256m",
            "--cpus",
            "1",
            "--pids-limit",
            "32",
            IMAGE,
            "python",
            "-c",
            check,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_clean_room_verifier_accepts_fix_and_rejects_exploit_preserving_patch(
    docker_available: bool,
) -> None:
    """Exercise hidden authorization tests without exposing them to candidate generation."""
    if not docker_available:
        pytest.skip("Docker is not available")

    verifier_image = _build_verifier_image()
    original = (SOURCE_DIR / "app.py").read_text(encoding="utf-8")
    fixed_source = original.replace(
        '    # VULNERABLE: the authenticated principal is never compared with document["owner"].\n',
        '    if document["owner"] != g.principal:\n        abort(404)\n',
    )
    assert fixed_source != original, "fixture source changed; review the expected patch"
    good_outcome, good_checks = _verify(_candidate(_diff(fixed_source)), verifier_image)

    exploit_preserving_source = original.replace(
        '# VULNERABLE: the authenticated principal is never compared with document["owner"].',
        "# The authenticated principal is still not checked against document ownership.",
    )
    exploit_outcome, exploit_checks = _verify(
        _candidate(_diff(exploit_preserving_source)), verifier_image
    )

    assert good_outcome is AssuranceOutcome.VERIFIED, good_checks
    assert exploit_outcome is AssuranceOutcome.REJECTED, exploit_checks
