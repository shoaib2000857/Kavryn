"""Real-Docker, end-to-end verification of the Change 6 repair loop.

Builds five patch candidates against the real fixture and runs each
through the full pipeline (source-integrity check, diff-policy check,
a real before/after Semgrep re-scan, the real clean-room verifier
container, and the assurance gate) to confirm the exact outcome
docs/IMPLEMENTATION_HANDOFF.md Change 6 requires: "good patch passes;
exploit-preserving, regression, test-gaming, and tampered-evidence
patches fail."
"""

from __future__ import annotations

import difflib
import hashlib
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.broker.adapter import AdapterDescriptor, AdapterLimits, AdapterPermissions
from aegis.domain.action import ActionRequest
from aegis.domain.base import ActorRole, Digest
from aegis.domain.policy import RiskTier
from aegis.evidence.store import InMemoryArtifactStore
from aegis.repair.candidate import PatchCandidate, changed_files
from aegis.repair.hashing import hash_source_tree
from aegis.repair.workspace import PatchApplyError, create_patch_workspace
from aegis.tools.findings import NormalizedFinding
from aegis.tools.static_analysis import ContainerStaticAnalysisAdapter, make_semgrep_adapter
from aegis.verifier.checks import (
    check_clean_room_tests,
    check_diff_policy,
    check_security_rescan,
    check_source_integrity,
)
from aegis.verifier.gate import evaluate_assurance
from aegis.verifier.models import AssuranceOutcome

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "ranges" / "path-traversal-v1"
SRC_DIR = FIXTURE_DIR / "src"
PUBLIC_TESTS_DIR = FIXTURE_DIR / "public_tests"
HIDDEN_TESTS_DIR = FIXTURE_DIR / "hidden_tests"
ANALYSIS_DOCKERFILE_DIR = REPO_ROOT / "docker" / "analysis-worker"
VERIFIER_DOCKERFILE_DIR = REPO_ROOT / "docker" / "verifier"

ORIGINAL_APP_PY = (SRC_DIR / "app.py").read_text()
ALLOWED_FILES = frozenset({"app.py"})


def _build_image(dockerfile_dir: Path, tag: str) -> str:
    subprocess.run(
        [
            "docker",
            "build",
            "-t",
            tag,
            "-f",
            str(dockerfile_dir / "Dockerfile"),
            str(dockerfile_dir),
        ],
        check=True,
        capture_output=True,
        timeout=600,
    )
    result = subprocess.run(
        ["docker", "inspect", tag, "--format={{.Id}}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


@pytest.fixture(scope="session")
def analysis_image_id() -> str:
    return _build_image(ANALYSIS_DOCKERFILE_DIR, "aegis-analysis-worker:repair-test")


@pytest.fixture(scope="session")
def verifier_image_id() -> str:
    return _build_image(VERIFIER_DOCKERFILE_DIR, "aegis-verifier:repair-test")


def _diff_for(patched_content: str) -> str:
    diff_lines = difflib.unified_diff(
        ORIGINAL_APP_PY.splitlines(keepends=True),
        patched_content.splitlines(keepends=True),
        fromfile="a/app.py",
        tofile="b/app.py",
    )
    return "".join(diff_lines)


def _candidate(diff: str, *, base_source_digest: Digest | None = None) -> PatchCandidate:
    digest = base_source_digest if base_source_digest is not None else hash_source_tree(SRC_DIR)
    return PatchCandidate(
        id="patch-int-0001",
        case_id="AGE-0001",
        base_repository="path-traversal-v1",
        base_source_digest=digest,
        diff=diff,
        diff_digest=Digest(digest=hashlib.sha256(diff.encode()).hexdigest()),
        files_changed=changed_files(diff),
        root_cause="unsanitized path join allows traversal outside BASE_DIR",
        repair_invariant="resolved path must remain within BASE_DIR",
        generated_at=datetime.now(UTC),
    )


def _scan_descriptor() -> AdapterDescriptor:
    return AdapterDescriptor(
        id="semgrep.scan",
        version=1,
        category="static-analysis",
        permissions=AdapterPermissions(filesystem="read-target"),
        risk_tier=RiskTier.R1_ANALYZE,
        limits=AdapterLimits(timeout_seconds=60, cpu=2, memory_mb=1024),
        parser="semgrep-json-v1",
    )


def _scan_request(*, request_id: str, source_dir: str) -> ActionRequest:
    return ActionRequest(
        id=request_id,
        case_id="AGE-0001",
        actor_id="reasoning_runtime:v1",
        role=ActorRole.REASONING_RUNTIME,
        action_type="scan.run",
        target_ref="workspace://AGE-0001/candidate",
        adapter="semgrep.scan",
        parameters={"source_dir": source_dir},
        reason="pre/post-patch security re-scan",
        requested_at=datetime.now(UTC),
    )


def _findings_for(
    adapter: ContainerStaticAnalysisAdapter, source_dir: str, request_id: str
) -> tuple[NormalizedFinding, ...]:
    result = adapter.run(
        _scan_request(request_id=request_id, source_dir=source_dir),
        capability_ref="capability://AGE-0001/cap-1",
    )
    return tuple(NormalizedFinding(**f) for f in result.output.get("findings", []))


def _run_pipeline(
    candidate: PatchCandidate, *, analysis_image_id: str, verifier_image_id: str
) -> AssuranceOutcome:
    checks = [
        check_source_integrity(candidate, trusted_source_dir=str(SRC_DIR)),
        check_diff_policy(candidate, allowed_files=ALLOWED_FILES),
    ]

    scan_adapter = make_semgrep_adapter(
        _scan_descriptor(),
        artifacts=InMemoryArtifactStore(),
        allowed_source_root=str(SRC_DIR),
        image_ref=analysis_image_id,
    )
    findings_before = _findings_for(scan_adapter, str(SRC_DIR), "scan-before")

    workspace: Path | None = None
    try:
        workspace = create_patch_workspace(str(SRC_DIR), candidate, allowed_files=ALLOWED_FILES)
    except PatchApplyError:
        workspace = None

    if workspace is not None:
        try:
            after_scan_adapter = make_semgrep_adapter(
                _scan_descriptor(),
                artifacts=InMemoryArtifactStore(),
                allowed_source_root=str(workspace),
                image_ref=analysis_image_id,
            )
            findings_after = _findings_for(after_scan_adapter, str(workspace), "scan-after")
            checks.append(check_security_rescan(findings_before, findings_after))
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    with tempfile.TemporaryDirectory() as tmp_dir:
        diff_file = Path(tmp_dir) / "patch.diff"
        diff_file.write_text(candidate.diff)
        checks.extend(
            check_clean_room_tests(
                image_ref=verifier_image_id,
                trusted_source_dir=str(SRC_DIR),
                diff_file=str(diff_file),
                public_tests_dir=str(PUBLIC_TESTS_DIR),
                hidden_tests_dir=str(HIDDEN_TESTS_DIR),
            )
        )

    return evaluate_assurance(tuple(checks))


GOOD_APP_PY = ORIGINAL_APP_PY.replace(
    "from flask import Flask, abort, request, send_file\n",
    "from flask import Flask, abort, request, send_file\nfrom werkzeug.utils import safe_join\n",
).replace(
    '    filename = request.args.get("filename", "")\n'
    "    # VULNERABLE: no path sanitization. A filename like\n"
    '    # "../../../../etc/passwd" escapes BASE_DIR entirely.\n'
    "    path = os.path.join(BASE_DIR, filename)\n"
    "    if not os.path.isfile(path):\n"
    "        abort(404)\n",
    '    filename = request.args.get("filename", "")\n'
    "    path = safe_join(BASE_DIR, filename)\n"
    "    if path is None or not os.path.isfile(path):\n"
    "        abort(404)\n",
)

EXPLOIT_PRESERVING_APP_PY = ORIGINAL_APP_PY.replace(
    "def download() -> object:\n",
    "def download() -> object:\n    # no-op: does not fix anything\n",
)

REGRESSION_BREAKING_APP_PY = ORIGINAL_APP_PY.replace(
    '    filename = request.args.get("filename", "")\n'
    "    # VULNERABLE: no path sanitization. A filename like\n"
    '    # "../../../../etc/passwd" escapes BASE_DIR entirely.\n'
    "    path = os.path.join(BASE_DIR, filename)\n"
    "    if not os.path.isfile(path):\n"
    "        abort(404)\n"
    "    return send_file(path)\n",
    "    abort(404)\n",
)

TEST_GAMING_APP_PY = ORIGINAL_APP_PY.replace(
    '    filename = request.args.get("filename", "")\n'
    "    # VULNERABLE: no path sanitization. A filename like\n"
    '    # "../../../../etc/passwd" escapes BASE_DIR entirely.\n'
    "    path = os.path.join(BASE_DIR, filename)\n",
    '    filename = request.args.get("filename", "")\n'
    '    if filename == "../secret.txt":\n'
    "        abort(404)\n"
    "    path = os.path.join(BASE_DIR, filename)\n",
)


@pytest.mark.parametrize(
    ("scenario_name", "patched_content", "digest_override", "expected"),
    [
        ("good_patch", GOOD_APP_PY, None, AssuranceOutcome.VERIFIED),
        ("exploit_preserving", EXPLOIT_PRESERVING_APP_PY, None, AssuranceOutcome.REJECTED),
        ("regression_breaking", REGRESSION_BREAKING_APP_PY, None, AssuranceOutcome.REJECTED),
        ("test_gaming", TEST_GAMING_APP_PY, None, AssuranceOutcome.REJECTED),
    ],
)
def test_repair_scenario_reaches_expected_assurance_outcome(
    scenario_name: str,
    patched_content: str,
    digest_override: Digest | None,
    expected: AssuranceOutcome,
    analysis_image_id: str,
    verifier_image_id: str,
) -> None:
    candidate = _candidate(_diff_for(patched_content), base_source_digest=digest_override)
    outcome = _run_pipeline(
        candidate, analysis_image_id=analysis_image_id, verifier_image_id=verifier_image_id
    )
    assert outcome is expected, scenario_name


def test_tampered_evidence_is_a_control_failure_regardless_of_diff_quality(
    analysis_image_id: str, verifier_image_id: str
) -> None:
    """A candidate claiming a base source digest that does not match the
    real pinned fixture must be a CONTROL_FAILURE even when the diff
    itself is the correct fix -- the evidence itself is untrustworthy."""
    candidate = _candidate(_diff_for(GOOD_APP_PY), base_source_digest=Digest(digest="f" * 64))
    outcome = _run_pipeline(
        candidate, analysis_image_id=analysis_image_id, verifier_image_id=verifier_image_id
    )
    assert outcome is AssuranceOutcome.CONTROL_FAILURE
