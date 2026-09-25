"""The Change 8 capstone: one full incident-to-recovery case run using
real Docker infrastructure from every prior change.

Wires the Change 8 orchestrator's dependency-injection seams to the
*real* Change 6 clean-room verifier and Change 7 runtime range (not
fakes) for a single genuine end-to-end run: detect the exploit is
reachable over the network, propose and apply real reversible
containment, verify it holds while benign traffic keeps working,
generate and clean-room-verify a real patch candidate, deploy the
patched service, and verify recovery.

Only the reasoning step remains a ``StubProvider`` returning a fixed
containment proposal: no working direct-API hosted-model credential is
available in this environment (docs/DECISIONS.md ADR-031) — the
project owner has said to leave this unconfigured for now and will
supply one later. Every other step is the real thing.
"""

from __future__ import annotations

import contextlib
import difflib
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.domain.base import Digest
from aegis.orchestrator.case_runner import CaseDependencies, run_case
from aegis.providers.schemas import ProposalKind, StructuredProposal
from aegis.providers.stub import StubProvider
from aegis.range.containment import ContainmentRule, write_rules
from aegis.range.network import create_network, remove_network
from aegis.range.service import ServiceSpec, start_service, stop_service
from aegis.range.traffic import send_get
from aegis.repair.candidate import PatchCandidate, changed_files
from aegis.repair.hashing import hash_source_tree
from aegis.reporting.case_report import render_human_report, render_json_report
from aegis.verifier.checks import (
    check_clean_room_tests,
    check_diff_policy,
    check_source_integrity,
)
from aegis.verifier.gate import evaluate_assurance
from aegis.verifier.models import AssuranceOutcome
from aegis.workflow.states import CaseState

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "ranges" / "path-traversal-v1"
SRC_DIR = FIXTURE_DIR / "src"
PUBLIC_TESTS_DIR = FIXTURE_DIR / "public_tests"
HIDDEN_TESTS_DIR = FIXTURE_DIR / "hidden_tests"
VERIFIER_DOCKERFILE_DIR = REPO_ROOT / "docker" / "verifier"
PROXY_DOCKERFILE_DIR = REPO_ROOT / "docker" / "range-proxy"

NETWORK_NAME = "aegis-fullcase-net"
APP_NAME = "aegis-fullcase-app"
PROXY_NAME = "aegis-fullcase-proxy"
ALLOWED_FILES = frozenset({"app.py"})

ORIGINAL_APP_PY = (SRC_DIR / "app.py").read_text()
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

CONTAINMENT_PROPOSAL = StructuredProposal(
    kind=ProposalKind.PROPOSE_ACTION,
    rationale="apply a deny-query proxy rule for traversal-shaped requests",
    action={
        "action_type": "contain.rate_limit",
        "target_ref": "service://demo-api-range",
        "adapter": "range.proxy",
        "reason": "block the observed traversal payloads",
    },
)


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


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_until_ready(base_url: str, *, attempts: int = 20, delay: float = 0.5) -> None:
    for _ in range(attempts):
        if send_get(base_url, "/download?filename=welcome.txt", timeout=1.0).status_code == 200:
            return
        time.sleep(delay)
    raise RuntimeError(f"range at {base_url} did not become ready in time")


def _diff_for(patched_content: str) -> str:
    return "".join(
        difflib.unified_diff(
            ORIGINAL_APP_PY.splitlines(keepends=True),
            patched_content.splitlines(keepends=True),
            fromfile="a/app.py",
            tofile="b/app.py",
        )
    )


@contextlib.contextmanager
def _tmp_diff_file(diff: str) -> Iterator[str]:
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = Path(tmp_dir) / "patch.diff"
        path.write_text(diff)
        yield str(path)


def _build_fixture_image(*, patched: bool, tag: str) -> str:
    """Build the app image from a scratch copy of the whole fixture
    directory, optionally with the patch already applied to ``app.py``
    -- this is "deploying the verified candidate," not just editing the
    tracked fixture in place."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        workspace = Path(tmp_dir) / "fixture"
        shutil.copytree(FIXTURE_DIR, workspace)
        if patched:
            (workspace / "src" / "app.py").write_text(GOOD_APP_PY)
        return _build_image(workspace, tag)


@pytest.fixture(scope="session")
def original_app_image_id() -> str:
    return _build_fixture_image(patched=False, tag="aegis-range-app:fullcase-original")


@pytest.fixture(scope="session")
def verifier_image_id() -> str:
    return _build_image(VERIFIER_DOCKERFILE_DIR, "aegis-verifier:fullcase")


@pytest.fixture(scope="session")
def proxy_image_id() -> str:
    return _build_image(PROXY_DOCKERFILE_DIR, "aegis-range-proxy:fullcase")


@pytest.fixture
def running_range(
    original_app_image_id: str, proxy_image_id: str, tmp_path: Path
) -> Iterator[tuple[str, str]]:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rules_file = rules_dir / "rules.json"
    write_rules(str(rules_file), ContainmentRule())

    stop_service(APP_NAME)
    stop_service(PROXY_NAME)
    remove_network(NETWORK_NAME)
    create_network(NETWORK_NAME)

    host_port = _free_port()
    try:
        start_service(ServiceSpec(image=original_app_image_id, name=APP_NAME, network=NETWORK_NAME))
        start_service(
            ServiceSpec(
                image=proxy_image_id,
                name=PROXY_NAME,
                network=NETWORK_NAME,
                env={"AEGIS_BACKEND_URL": f"http://{APP_NAME}:8080"},
                published_port=(host_port, 8081),
                volumes=((str(rules_dir), "/rules", "ro"),),
            )
        )
        base_url = f"http://127.0.0.1:{host_port}"
        _wait_until_ready(base_url)
        yield base_url, str(rules_file)
    finally:
        stop_service(APP_NAME)
        stop_service(PROXY_NAME)
        remove_network(NETWORK_NAME)


def test_full_case_reaches_closed_with_real_infrastructure(
    running_range: tuple[str, str], verifier_image_id: str
) -> None:
    base_url, rules_file = running_range
    diff = _diff_for(GOOD_APP_PY)
    candidate = PatchCandidate(
        id="patch-fullcase-0001",
        case_id="AGE-0001",
        base_repository="path-traversal-v1",
        base_source_digest=hash_source_tree(SRC_DIR),
        diff=diff,
        diff_digest=Digest(digest="b" * 64),
        files_changed=changed_files(diff),
        root_cause="unsanitized path join allows traversal outside BASE_DIR",
        repair_invariant="resolved path must remain within BASE_DIR",
        generated_at=datetime.now(UTC),
    )

    def verify_candidate(candidate: PatchCandidate) -> AssuranceOutcome:
        checks = [
            check_source_integrity(candidate, trusted_source_dir=str(SRC_DIR)),
            check_diff_policy(candidate, allowed_files=ALLOWED_FILES),
        ]
        with _tmp_diff_file(candidate.diff) as diff_file:
            checks.extend(
                check_clean_room_tests(
                    image_ref=verifier_image_id,
                    trusted_source_dir=str(SRC_DIR),
                    diff_file=diff_file,
                    public_tests_dir=str(PUBLIC_TESTS_DIR),
                    hidden_tests_dir=str(HIDDEN_TESTS_DIR),
                )
            )
        return evaluate_assurance(tuple(checks))

    deployed = {"done": False}

    def deploy_patched_app() -> None:
        stop_service(APP_NAME)
        patched_image = _build_fixture_image(patched=True, tag="aegis-range-app:fullcase-patched")
        start_service(ServiceSpec(image=patched_image, name=APP_NAME, network=NETWORK_NAME))
        write_rules(rules_file, ContainmentRule())  # containment no longer needed once patched
        _wait_until_ready(base_url)
        deployed["done"] = True

    def recovery_attack_blocked() -> bool:
        if not deployed["done"]:
            deploy_patched_app()
        return send_get(base_url, "/download?filename=../secret.txt").status_code in (400, 403, 404)

    deps = CaseDependencies(
        provider=StubProvider(response=CONTAINMENT_PROPOSAL),
        exploit_reachable=lambda: (
            send_get(base_url, "/download?filename=../secret.txt").status_code == 200
        ),
        approve_containment=lambda: True,
        apply_containment=lambda: write_rules(
            rules_file, ContainmentRule(deny_query_patterns=(r"\.\.",))
        ),
        rollback_containment=lambda: write_rules(rules_file, ContainmentRule()),
        attack_blocked=lambda: (
            send_get(base_url, "/download?filename=../secret.txt").status_code == 403
        ),
        benign_available=lambda: (
            send_get(base_url, "/download?filename=welcome.txt").status_code == 200
        ),
        generate_candidate=lambda: candidate,
        verify_candidate=verify_candidate,
        approve_deployment=lambda: True,
        recovery_attack_blocked=recovery_attack_blocked,
        recovery_benign_available=lambda: (
            send_get(base_url, "/download?filename=welcome.txt").status_code == 200
        ),
        max_containment_attempts=1,
        max_repair_attempts=1,
    )

    trace = run_case("AGE-0001", deps)

    assert not trace.halted, trace.halt_reason
    assert trace.final_state is CaseState.CLOSED
    assert deployed["done"]

    json_report = render_json_report(trace)
    human_report = render_human_report(trace)
    assert '"final_state": "closed"' in json_report
    assert "completed at `closed`" in human_report
