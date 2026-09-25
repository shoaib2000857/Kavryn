"""Repeated live-model trials of the Change 8 case orchestrator against the
one Layer 0 fixture this project has (``ranges/path-traversal-v1``), using a
real local Ollama model instead of the stub provider.

This is deliberately narrow and says so in its own output: Layers 1-4 of
docs/BENCHMARKS_AND_DATASETS.md's evaluation ladder are not wired into this
codebase (OQ-008 is still open), so there is no external benchmark corpus to
run yet. What this script *can* honestly measure, with real evidence, is how
reliably the orchestrator's live containment-proposal step (the one part of
Change 8 that talks to a model at all) produces a usable, schema-valid
proposal against the one fixture that exists, for a given local model -- not
a claim about repair or detection capability in general.

Not part of the pytest suite (it starts real Docker containers repeatedly
and takes minutes to run); invoke directly:

    .venv/bin/python scripts/bench_live_model.py --model llama3.1:8b --trials 5
"""

from __future__ import annotations

import argparse
import difflib
import json
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from aegis.domain.base import Digest  # noqa: E402
from aegis.domain.policy import RiskTier  # noqa: E402
from aegis.orchestrator.case_runner import CaseDependencies, run_case  # noqa: E402
from aegis.providers.hosted import (  # noqa: E402
    HostedOpenAICompatibleProvider,
    HostedProviderConfig,
)
from aegis.providers.schemas import ToolDescriptor  # noqa: E402
from aegis.range.containment import ContainmentRule, write_rules  # noqa: E402
from aegis.range.network import create_network, remove_network  # noqa: E402
from aegis.range.service import ServiceSpec, start_service, stop_service  # noqa: E402
from aegis.range.traffic import send_get  # noqa: E402
from aegis.repair.candidate import PatchCandidate, changed_files  # noqa: E402
from aegis.repair.hashing import hash_source_tree  # noqa: E402
from aegis.verifier.models import AssuranceOutcome  # noqa: E402
from aegis.workflow.states import CaseState  # noqa: E402

FIXTURE_DIR = REPO_ROOT / "ranges" / "path-traversal-v1"
SRC_DIR = FIXTURE_DIR / "src"
PROXY_DOCKERFILE_DIR = REPO_ROOT / "docker" / "range-proxy"

NETWORK_NAME = "aegis-bench-net"
APP_NAME = "aegis-bench-app"
PROXY_NAME = "aegis-bench-proxy"

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


def _build_image(dockerfile_dir: Path, tag: str) -> None:
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="llama3.1:8b")
    parser.add_argument("--base-url", default="http://localhost:11434/v1")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument(
        "--out", type=Path, default=None, help="optional path to write JSON results"
    )
    args = parser.parse_args()

    print("Building fixture images (app + proxy)...")
    _build_image(FIXTURE_DIR, "aegis-range-app:bench")
    _build_image(PROXY_DOCKERFILE_DIR, "aegis-range-proxy:bench")

    stop_service(APP_NAME)
    stop_service(PROXY_NAME)
    remove_network(NETWORK_NAME)
    create_network(NETWORK_NAME)

    rules_dir = Path("/tmp/aegis-bench-rules")
    rules_dir.mkdir(exist_ok=True)
    rules_file = str(rules_dir / "rules.json")
    write_rules(rules_file, ContainmentRule())
    host_port = _free_port()

    diff = "".join(
        difflib.unified_diff(
            ORIGINAL_APP_PY.splitlines(keepends=True),
            GOOD_APP_PY.splitlines(keepends=True),
            fromfile="a/app.py",
            tofile="b/app.py",
        )
    )
    candidate = PatchCandidate(
        id="patch-bench-0001",
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
    containment_tools = (
        ToolDescriptor(
            id="range.proxy",
            category="network containment",
            risk_tier=RiskTier.R3_REVERSIBLE_RESPONSE,
            description="Applies a reversible deny-query proxy rule in front of the range.",
        ),
    )

    results: list[dict[str, object]] = []
    elapsed_times: list[float] = []
    try:
        start_service(
            ServiceSpec(image="aegis-range-app:bench", name=APP_NAME, network=NETWORK_NAME)
        )
        start_service(
            ServiceSpec(
                image="aegis-range-proxy:bench",
                name=PROXY_NAME,
                network=NETWORK_NAME,
                env={"AEGIS_BACKEND_URL": f"http://{APP_NAME}:8080"},
                published_port=(host_port, 8081),
                volumes=((str(rules_dir), "/rules", "ro"),),
            )
        )
        base_url = f"http://127.0.0.1:{host_port}"
        _wait_until_ready(base_url)

        provider = HostedOpenAICompatibleProvider(
            HostedProviderConfig(base_url=args.base_url, model=args.model, max_repair_attempts=2),
            api_key="ollama",
        )

        print(f"\nRunning {args.trials} trial(s) against model={args.model!r}...\n")
        for trial in range(1, args.trials + 1):
            write_rules(rules_file, ContainmentRule())
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
                verify_candidate=lambda _c: AssuranceOutcome.VERIFIED,
                approve_deployment=lambda: True,
                recovery_attack_blocked=lambda: True,
                recovery_benign_available=lambda: True,
                containment_tools=containment_tools,
                max_containment_attempts=1,
                max_repair_attempts=1,
            )
            calls_before = len(provider.calls)
            t0 = time.monotonic()
            trace = run_case("AGE-0001", deps)
            elapsed = time.monotonic() - t0
            calls_made = len(provider.calls) - calls_before

            outcome = "CLOSED" if trace.final_state is CaseState.CLOSED else "HALTED"
            record = {
                "trial": trial,
                "outcome": outcome,
                "final_state": trace.final_state.value,
                "halted": trace.halted,
                "halt_reason": trace.halt_reason,
                "elapsed_seconds": round(elapsed, 1),
                "provider_calls": calls_made,
            }
            results.append(record)
            elapsed_times.append(elapsed)
            print(
                f"trial {trial}: {outcome} (state={trace.final_state.value}, {elapsed:.1f}s)"
                + (f" -- {trace.halt_reason}" if trace.halted else "")
            )
    finally:
        stop_service(APP_NAME)
        stop_service(PROXY_NAME)
        remove_network(NETWORK_NAME)

    n = len(results)
    closed = sum(1 for r in results if r["outcome"] == "CLOSED")
    avg_latency = sum(elapsed_times) / n if n else 0.0
    print(f"\n=== summary: model={args.model} trials={n} ===")
    print(f"reached CLOSED: {closed}/{n}")
    print(f"average wall time per case: {avg_latency:.1f}s")

    if args.out is not None:
        args.out.write_text(json.dumps({"model": args.model, "trials": results}, indent=2) + "\n")
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
