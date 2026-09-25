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

For the configured OpenAI-compatible endpoint, set ``LLM_URL`` and
``LLM_API_KEY`` in the environment and run one warm-model trial:

    .venv/bin/python scripts/bench_live_model.py --provider hosted --trials 1
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from aegis.broker.broker import ActionBroker  # noqa: E402
from aegis.broker.registry import AdapterRegistry  # noqa: E402
from aegis.core.coordinator import ActionTransactionCoordinator  # noqa: E402
from aegis.domain.action import ActionRequest  # noqa: E402
from aegis.domain.base import Digest  # noqa: E402
from aegis.domain.case import Case  # noqa: E402
from aegis.domain.policy import RiskTier  # noqa: E402
from aegis.domain.scope import (  # noqa: E402
    ActionsPolicy,
    Authorization,
    Budgets,
    FilesystemPolicy,
    NetworkPolicy,
    ScopePolicy,
    ServiceTarget,
    Targets,
    ToolsPolicy,
)
from aegis.evidence.audit import InMemoryAuditSink  # noqa: E402
from aegis.evidence.store import InMemoryArtifactStore, sha256_digest  # noqa: E402
from aegis.investigation.correlation import (  # noqa: E402
    CorrelationReport,
    RouteSourceBinding,
    correlate_evidence,
)
from aegis.orchestrator.actions import BrokeredDefenderActions  # noqa: E402
from aegis.orchestrator.case_runner import CaseDependencies, run_case  # noqa: E402
from aegis.policy.approval import Approval, ApprovalDecision  # noqa: E402
from aegis.providers.hosted import (  # noqa: E402
    HostedOpenAICompatibleProvider,
    HostedProviderConfig,
)
from aegis.providers.schemas import ToolDescriptor  # noqa: E402
from aegis.range.adapter import ProxyRuleAdapter  # noqa: E402
from aegis.range.containment import ContainmentRule, write_rules  # noqa: E402
from aegis.range.deployment import RangeDeploymentAdapter  # noqa: E402
from aegis.range.network import create_network, remove_network  # noqa: E402
from aegis.range.provenance import DeploymentProvenance  # noqa: E402
from aegis.range.service import ServiceSpec, container_ip, start_service, stop_service  # noqa: E402
from aegis.range.traffic import send_get  # noqa: E402
from aegis.repair.candidate import PatchCandidate, changed_files  # noqa: E402
from aegis.repair.hashing import hash_source_tree  # noqa: E402
from aegis.telemetry.events import parse_proxy_log_line  # noqa: E402
from aegis.tools.findings import NormalizedFinding  # noqa: E402
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


def _wait_until_ready(base_url: str, *, attempts: int = 20, delay: float = 0.5) -> None:
    for _ in range(attempts):
        if send_get(base_url, "/download?filename=welcome.txt", timeout=1.0).status_code == 200:
            return
        time.sleep(delay)
    raise RuntimeError(f"range at {base_url} did not become ready in time")


def _oracle_seeded_investigation(
    *, base_image: str, now: datetime, artifacts: InMemoryArtifactStore
) -> CorrelationReport:
    """Build the proposal-reliability task from real range logs and known fixture truth.

    The static finding is oracle-seeded on purpose: this script measures the
    live model's containment-proposal reliability, not attack detection or
    scanner performance. That distinction is exported with every trial.
    """
    logs = subprocess.run(
        ["docker", "logs", "--tail", "200", PROXY_NAME],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout
    events = tuple(
        parse_proxy_log_line(
            line,
            case_id="AGE-0001",
            event_id=f"benchmark-event-{index}",
            artifacts=artifacts,
        )
        for index, line in enumerate(logs.splitlines())
        if line.startswith("{")
    )
    source_digest = hash_source_tree(SRC_DIR)
    finding = NormalizedFinding(
        tool="semgrep",
        rule_id="python.lang.security.audit.path-traversal",
        file="app.py",
        line=23,
        severity="ERROR",
        message="oracle-supplied fixture ground truth, not scanner output",
    )
    deployment = DeploymentProvenance(
        case_id="AGE-0001",
        container_name=APP_NAME,
        image_digest=base_image,
        source_repository="path-traversal-v1",
        source_commit_digest=source_digest,
        deployed_at=now,
    )
    finding_digest = artifacts.put(finding.model_dump_json().encode("utf-8"))
    deployment_digest = artifacts.put(deployment.model_dump_json().encode("utf-8"))
    return correlate_evidence(
        case_id="AGE-0001",
        events=events,
        findings=(finding,),
        bindings=(RouteSourceBinding(route_prefix="/download", source_file="app.py"),),
        scan_source_digest=source_digest,
        deployment=deployment,
        finding_evidence_ref=f"artifact://AGE-0001/sha256/{finding_digest.digest}",
        deployment_evidence_ref=f"artifact://AGE-0001/sha256/{deployment_digest.digest}",
    )


def _brokered_actions(
    rules_file: str,
    now: datetime,
    *,
    base_image: str,
    base_url: str,
) -> BrokeredDefenderActions:
    scope = ScopePolicy(
        case_id="AGE-0001",
        version=1,
        authorization=Authorization(expires_at=now + timedelta(hours=1)),
        targets=Targets(services=(ServiceTarget(id="demo-api-range", network=NETWORK_NAME),)),
        network=NetworkPolicy(),
        filesystem=FilesystemPolicy(),
        tools=ToolsPolicy(allow=("range.proxy", "range.deployment")),
        actions=ActionsPolicy(
            approval=(
                "contain.rate_limit",
                "contain.rollback",
                "deployment.rollout",
                "deployment.rollback",
            ),
            deny=("host.shell", "audit.modify"),
        ),
        budgets=Budgets(
            tool_calls=30,
            model_tokens=100_000,
            wall_time_seconds=1800,
            spend_usd=20,
        ),
    )
    case = Case(
        id="AGE-0001",
        title="Aegis local model benchmark case",
        created_at=now,
        created_by="operator:alice",
        scope_ref="scope://AGE-0001/1",
        scope_digest=sha256_digest(scope.model_dump_json().encode()),
    )
    registry = AdapterRegistry()
    registry.register(ProxyRuleAdapter(rules_file))
    registry.register(
        RangeDeploymentAdapter(
            fixture_dir=str(FIXTURE_DIR),
            source_subdirectory="src",
            allowed_files=frozenset({"app.py"}),
            base_source_digest=hash_source_tree(str(SRC_DIR)),
            base_image=base_image,
            service=ServiceSpec(image=base_image, name=APP_NAME, network=NETWORK_NAME),
            target_ref="service://demo-api-range",
            rules_file=rules_file,
            readiness_probe=lambda: (
                send_get(base_url, "/download?filename=welcome.txt", timeout=1.0).status_code == 200
            ),
        )
    )
    broker = ActionBroker(
        registry=registry,
        audit=InMemoryAuditSink(),
        artifacts=InMemoryArtifactStore(),
    )

    def approve(request: ActionRequest) -> Approval:
        return Approval(
            id=f"approval-{request.id}",
            case_id=request.case_id,
            subject_ref=f"action-request://{request.case_id}/{request.id}",
            requested_at=now,
            expires_at=now + timedelta(minutes=5),
            decision=ApprovalDecision.APPROVED,
            decided_by="operator:alice",
            decided_at=now,
        )

    return BrokeredDefenderActions(
        coordinator=ActionTransactionCoordinator(broker),
        case=case,
        scope=scope,
        approval_provider=approve,
        policy_version="benchmark-scope-v1",
        clock=lambda: now,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("ollama", "hosted"), default="ollama")
    parser.add_argument("--model", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key-env", default="LLM_API_KEY")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument(
        "--out", type=Path, default=None, help="optional path to write JSON results"
    )
    args = parser.parse_args()

    if args.provider == "hosted":
        endpoint = args.base_url or os.environ.get("LLM_URL", "")
        api_key = os.environ.get(args.api_key_env, "")
        model = args.model or os.environ.get("LLM_MODEL", "qwen38")
        if not endpoint or not api_key:
            parser.error(
                "hosted mode requires --base-url or LLM_URL and the "
                f"{args.api_key_env} environment variable"
            )
        parsed_endpoint = urlsplit(endpoint)
        if parsed_endpoint.scheme != "https" and parsed_endpoint.hostname not in {
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            parser.error("refusing to send the API key to a non-local HTTP endpoint")
        if not endpoint.rstrip("/").endswith("/v1"):
            endpoint = endpoint.rstrip("/") + "/v1"
        reasoning_effort = "none"
    else:
        endpoint = args.base_url or "http://localhost:11434/v1"
        model = args.model or "llama3.1:8b"
        api_key = "ollama"
        reasoning_effort = None

    print("Building fixture images (app + proxy)...")
    base_image = _build_image(FIXTURE_DIR, "aegis-range-app:bench")
    _build_image(PROXY_DOCKERFILE_DIR, "aegis-range-proxy:bench")

    stop_service(APP_NAME)
    stop_service(PROXY_NAME)
    remove_network(NETWORK_NAME)
    create_network(NETWORK_NAME)

    rules_dir = Path("/tmp/aegis-bench-rules")
    rules_dir.mkdir(exist_ok=True)
    rules_file = str(rules_dir / "rules.json")
    write_rules(rules_file, ContainmentRule())

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
        diff_digest=Digest(digest=hashlib.sha256(diff.encode()).hexdigest()),
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
                volumes=((str(rules_dir), "/rules", "ro"),),
            )
        )
        base_url = f"http://{container_ip(PROXY_NAME)}:8081"
        _wait_until_ready(base_url)

        provider = HostedOpenAICompatibleProvider(
            HostedProviderConfig(
                base_url=endpoint,
                model=model,
                max_repair_attempts=2,
                timeout_seconds=180,
                reasoning_effort=reasoning_effort,
            ),
            api_key=api_key,
        )

        print(
            f"\nRunning {args.trials} trial(s) against "
            f"provider={args.provider!r} model={model!r}...\n"
        )
        for trial in range(1, args.trials + 1):
            stop_service(APP_NAME)
            start_service(ServiceSpec(image=base_image, name=APP_NAME, network=NETWORK_NAME))
            write_rules(rules_file, ContainmentRule())
            trial_now = datetime.now(UTC)
            investigation_artifacts = InMemoryArtifactStore()

            def investigate(
                local_base_image: str = base_image,
                local_now: datetime = trial_now,
                local_artifacts: InMemoryArtifactStore = investigation_artifacts,
            ) -> CorrelationReport:
                return _oracle_seeded_investigation(
                    base_image=local_base_image,
                    now=local_now,
                    artifacts=local_artifacts,
                )

            deps = CaseDependencies(
                provider=provider,
                brokered_actions=_brokered_actions(
                    rules_file,
                    trial_now,
                    base_image=base_image,
                    base_url=base_url,
                ),
                exploit_reachable=lambda: (
                    send_get(base_url, "/download?filename=../secret.txt").status_code == 200
                ),
                attack_blocked=lambda: (
                    send_get(base_url, "/download?filename=../secret.txt").status_code
                    in (400, 403, 404)
                ),
                benign_available=lambda: (
                    send_get(base_url, "/download?filename=welcome.txt").status_code == 200
                ),
                generate_candidate=lambda: candidate,
                verify_candidate=lambda _c: AssuranceOutcome.VERIFIED,
                deployment_target_ref="service://demo-api-range",
                recovery_attack_blocked=lambda: (
                    send_get(base_url, "/download?filename=../secret.txt").status_code
                    in (400, 403, 404)
                ),
                recovery_benign_available=lambda: (
                    send_get(base_url, "/download?filename=welcome.txt").status_code == 200
                ),
                investigate=investigate,
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
                "investigation_mode": "oracle_seeded_static_finding",
                "correlated_hypotheses": (
                    trace.investigation.correlated_pairs if trace.investigation else 0
                ),
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
    print(f"\n=== summary: provider={args.provider} model={model} trials={n} ===")
    print(f"reached CLOSED: {closed}/{n}")
    print(f"average wall time per case: {avg_latency:.1f}s")

    if args.out is not None:
        args.out.write_text(
            json.dumps({"provider": args.provider, "model": model, "trials": results}, indent=2)
            + "\n"
        )
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
