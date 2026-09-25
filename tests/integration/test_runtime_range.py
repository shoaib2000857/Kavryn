"""Real-Docker, end-to-end verification of the Change 7 runtime range.

Deploys the real vulnerable fixture and the real containment proxy on
an isolated network, confirms the exploit is reachable over the
network before containment, applies a reversible containment rule,
confirms the exploit is blocked while benign traffic keeps working,
then rolls the rule back and confirms the exploit is reachable again --
exactly docs/IMPLEMENTATION_HANDOFF.md Change 7's verification bullet:
"deterministic pre-attack, attack, containment, and availability
checks."
"""

from __future__ import annotations

import socket
import subprocess
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.domain.base import Digest
from aegis.evidence.store import InMemoryArtifactStore
from aegis.range.containment import ContainmentRule, write_rules
from aegis.range.network import create_network, remove_network
from aegis.range.provenance import DeploymentProvenance
from aegis.range.service import ServiceSpec, container_logs, start_service, stop_service
from aegis.range.traffic import send_get
from aegis.repair.hashing import hash_source_tree
from aegis.telemetry.events import EventClassification, parse_proxy_log_line

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "ranges" / "path-traversal-v1"
SRC_DIR = FIXTURE_DIR / "src"
APP_DOCKERFILE_DIR = FIXTURE_DIR
PROXY_DOCKERFILE_DIR = REPO_ROOT / "docker" / "range-proxy"

NETWORK_NAME = "aegis-range-inttest"
APP_NAME = "aegis-range-inttest-app"
PROXY_NAME = "aegis-range-inttest-proxy"


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


@pytest.fixture(scope="session")
def app_image_id() -> str:
    return _build_image(APP_DOCKERFILE_DIR, "aegis-range-app:inttest")


@pytest.fixture(scope="session")
def proxy_image_id() -> str:
    return _build_image(PROXY_DOCKERFILE_DIR, "aegis-range-proxy:inttest")


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


def _wait_until_ready(base_url: str, *, attempts: int = 20, delay: float = 0.5) -> None:
    for _ in range(attempts):
        outcome = send_get(base_url, "/download?filename=welcome.txt", timeout=1.0)
        if outcome.status_code == 200:
            return
        time.sleep(delay)
    raise RuntimeError(f"range at {base_url} did not become ready in time")


def test_pre_attack_baseline_benign_traffic_works(running_range: tuple[str, str]) -> None:
    base_url, _ = running_range
    outcome = send_get(base_url, "/download?filename=welcome.txt")
    assert outcome.status_code == 200


def test_pre_containment_the_exploit_succeeds_over_the_network(
    running_range: tuple[str, str],
) -> None:
    """The vulnerability is genuinely reachable as a live network service,
    not just via direct source-code analysis."""
    base_url, _ = running_range
    outcome = send_get(base_url, "/download?filename=../secret.txt")
    assert outcome.status_code == 200


def test_containment_blocks_the_attack_while_preserving_benign_availability(
    running_range: tuple[str, str],
) -> None:
    base_url, rules_file = running_range
    write_rules(rules_file, ContainmentRule(deny_query_patterns=(r"\.\.",)))

    attack_outcome = send_get(base_url, "/download?filename=../secret.txt")
    benign_outcome = send_get(base_url, "/download?filename=welcome.txt")

    assert attack_outcome.status_code == 403
    assert benign_outcome.status_code == 200


def test_rollback_restores_the_original_reachability(running_range: tuple[str, str]) -> None:
    base_url, rules_file = running_range
    write_rules(rules_file, ContainmentRule(deny_query_patterns=(r"\.\.",)))
    assert send_get(base_url, "/download?filename=../secret.txt").status_code == 403

    write_rules(rules_file, ContainmentRule())  # rollback: the original (empty) rule
    assert send_get(base_url, "/download?filename=../secret.txt").status_code == 200


def test_proxy_telemetry_normalizes_into_correctly_classified_events(
    running_range: tuple[str, str],
) -> None:
    base_url, _ = running_range
    send_get(base_url, "/download?filename=welcome.txt")
    send_get(base_url, "/download?filename=../secret.txt")

    raw_logs = container_logs(PROXY_NAME)
    lines = [line for line in raw_logs.splitlines() if line.strip().startswith("{")]
    assert lines, "expected at least one structured log line from the proxy"

    store = InMemoryArtifactStore()
    events = [
        parse_proxy_log_line(line, case_id="AGE-0001", event_id=f"evt-{i}", artifacts=store)
        for i, line in enumerate(lines)
    ]
    classifications = {event.inferred_classification for event in events}
    assert EventClassification.BENIGN in classifications
    assert EventClassification.SUSPICIOUS in classifications


def test_deployment_provenance_ties_the_container_to_the_pinned_source(
    app_image_id: str,
) -> None:
    provenance = DeploymentProvenance(
        case_id="AGE-0001",
        container_name=APP_NAME,
        image_digest=app_image_id,
        source_repository="path-traversal-v1",
        source_commit_digest=hash_source_tree(SRC_DIR),
        deployed_at=datetime.now(UTC),
    )
    # Provenance must be independently reproducible from the same source tree.
    assert provenance.source_commit_digest == hash_source_tree(SRC_DIR)
    assert provenance.source_commit_digest != Digest(digest="f" * 64)
