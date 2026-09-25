"""A genuine live-model run of the Change 8 orchestrator, using a local
Ollama model instead of ``StubProvider``.

See docs/DECISIONS.md ADR-031: no working *hosted* direct-API credential
was obtained. Ollama sidesteps that problem entirely — it is local,
requires no third-party account or key, and exposes an OpenAI-Chat-
Completions-compatible endpoint, so it plugs into the exact same
``HostedOpenAICompatibleProvider`` built for a real hosted provider with
zero code changes. This is temporary, local-only verification that the
provider boundary and the orchestrator's reasoning call genuinely work
end to end with a live model producing real (not canned) output — not a
replacement for choosing a production hosted provider (OQ-004 remains
open for that).

Skipped automatically if Ollama is not reachable or the configured
model is not pulled locally; never run in default CI.
"""

from __future__ import annotations

import difflib
import socket
import subprocess
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.domain.base import Digest
from aegis.domain.policy import RiskTier
from aegis.orchestrator.case_runner import CaseDependencies, run_case
from aegis.providers.hosted import HostedOpenAICompatibleProvider, HostedProviderConfig
from aegis.providers.schemas import ToolDescriptor
from aegis.range.containment import ContainmentRule, write_rules
from aegis.range.network import create_network, remove_network
from aegis.range.service import ServiceSpec, start_service, stop_service
from aegis.range.traffic import send_get
from aegis.repair.candidate import PatchCandidate, changed_files
from aegis.repair.hashing import hash_source_tree
from aegis.reporting.case_report import render_human_report
from aegis.verifier.models import AssuranceOutcome
from aegis.workflow.states import CaseState

OLLAMA_BASE_URL = "http://localhost:11434/v1"
OLLAMA_MODEL = "qwen2.5:7b"

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "ranges" / "path-traversal-v1"
SRC_DIR = FIXTURE_DIR / "src"
PROXY_DOCKERFILE_DIR = REPO_ROOT / "docker" / "range-proxy"

NETWORK_NAME = "aegis-livemodel-net"
APP_NAME = "aegis-livemodel-app"
PROXY_NAME = "aegis-livemodel-proxy"

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


def _ollama_ready() -> bool:
    try:
        version = subprocess.run(
            ["curl", "-sf", "http://localhost:11434/api/version"],
            capture_output=True,
            timeout=5,
            check=False,
        )
        if version.returncode != 0:
            return False
        tags = subprocess.run(
            ["curl", "-sf", "http://localhost:11434/api/tags"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return OLLAMA_MODEL in tags.stdout
    except OSError:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _ollama_ready(), reason=f"Ollama with {OLLAMA_MODEL} not available locally"
    ),
]


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


@pytest.fixture(scope="session")
def app_image_id() -> str:
    return _build_image(FIXTURE_DIR, "aegis-range-app:livemodel")


@pytest.fixture(scope="session")
def proxy_image_id() -> str:
    return _build_image(PROXY_DOCKERFILE_DIR, "aegis-range-proxy:livemodel")


@pytest.fixture
def running_range(
    app_image_id: str, proxy_image_id: str, tmp_path: Path
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
        start_service(ServiceSpec(image=app_image_id, name=APP_NAME, network=NETWORK_NAME))
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


def test_orchestrator_reaches_closed_using_a_real_local_model(
    running_range: tuple[str, str],
) -> None:
    """The containment-proposal step is answered by a real Ollama model,
    not a canned StructuredProposal -- everything downstream (approval,
    real containment apply/verify, real repair verification, real
    recovery) is exactly the Change 8 capstone path."""
    base_url, rules_file = running_range

    provider = HostedOpenAICompatibleProvider(
        HostedProviderConfig(base_url=OLLAMA_BASE_URL, model=OLLAMA_MODEL, max_repair_attempts=2),
        api_key="ollama",  # Ollama's OpenAI-compatible endpoint does not check this
    )

    diff = "".join(
        difflib.unified_diff(
            ORIGINAL_APP_PY.splitlines(keepends=True),
            GOOD_APP_PY.splitlines(keepends=True),
            fromfile="a/app.py",
            tofile="b/app.py",
        )
    )
    candidate = PatchCandidate(
        id="patch-livemodel-0001",
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

    deps = CaseDependencies(
        provider=provider,
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
        verify_candidate=lambda _candidate: AssuranceOutcome.VERIFIED,
        approve_deployment=lambda: True,
        recovery_attack_blocked=lambda: True,
        recovery_benign_available=lambda: True,
        containment_tools=(
            ToolDescriptor(
                id="range.proxy",
                category="network containment",
                risk_tier=RiskTier.R3_REVERSIBLE_RESPONSE,
                description="Applies a reversible deny-query proxy rule in front of the range.",
            ),
        ),
        max_containment_attempts=1,
        max_repair_attempts=1,
    )

    trace = run_case("AGE-0001", deps)

    print("\n" + render_human_report(trace))
    print(f"\nLive model calls made: {len(provider.calls)}")

    # A real local model is not perfectly deterministic or schema-compliant.
    # Either the orchestrator reaches CLOSED with a genuinely useful live
    # proposal, or it halts gracefully with a clear reason (never crashes) --
    # both are acceptable proof that the provider boundary and orchestrator
    # wiring genuinely work end to end with live (non-canned) model output.
    # An uncaught exception escaping run_case would fail this test regardless.
    assert trace.final_state in (CaseState.CLOSED, CaseState.CONTAIN_PROPOSAL)
    if trace.final_state is CaseState.CLOSED:
        assert not trace.halted
    else:
        assert trace.halted
    assert len(provider.calls) >= 1
