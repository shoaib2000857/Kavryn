"""Exercise the object-authorization scenario through the brokered case flow.

The default test uses deterministic proposals and patches. A separately gated
live test uses the configured model for containment reasoning and patch source,
then verifies and deploys through the same controlled path. Both are synthetic
fixture integrations; neither is a standard benchmark score.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import subprocess
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import pytest

from aegis.broker.broker import ActionBroker
from aegis.broker.registry import AdapterRegistry
from aegis.core.coordinator import ActionTransactionCoordinator
from aegis.domain.action import ActionRequest
from aegis.domain.audit import AuditEventType
from aegis.domain.base import Digest
from aegis.domain.case import Case
from aegis.domain.policy import RiskTier
from aegis.domain.scope import (
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
from aegis.evidence.audit import InMemoryAuditSink
from aegis.evidence.store import InMemoryArtifactStore, sha256_digest
from aegis.investigation.correlation import RouteSourceBinding
from aegis.investigation.range import RangeEvidenceInvestigator, make_range_semgrep_adapter
from aegis.orchestrator.actions import BrokeredDefenderActions
from aegis.orchestrator.case_runner import CaseDependencies, run_case
from aegis.policy.approval import Approval, ApprovalDecision
from aegis.providers.base import ReasoningProvider
from aegis.providers.hosted import HostedOpenAICompatibleProvider, HostedProviderConfig
from aegis.providers.schemas import StructuredProposal, ToolDescriptor
from aegis.providers.stub import StubProvider
from aegis.range.adapter import ProxyRuleAdapter
from aegis.range.containment import ContainmentRule, write_rules
from aegis.range.deployment import RangeDeploymentAdapter
from aegis.range.logs import ProxyLogsAdapter
from aegis.range.network import create_network, remove_network
from aegis.range.service import (
    ServiceSpec,
    container_ip,
    container_logs,
    start_service,
    stop_service,
)
from aegis.range.traffic import send_get
from aegis.repair.candidate import PatchCandidate, changed_files
from aegis.repair.hashing import hash_source_tree
from aegis.repair.provider import HostedPatchProvider, PatchGenerationRequest
from aegis.verifier.checks import check_clean_room_tests, check_diff_policy, check_source_integrity
from aegis.verifier.gate import evaluate_assurance
from aegis.verifier.models import AssuranceOutcome, CheckResult
from aegis.workflow.states import CaseState

pytestmark = pytest.mark.integration

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPOSITORY_ROOT / "ranges" / "object-authorization-v1"
SOURCE = FIXTURE / "src"
PUBLIC_TESTS = FIXTURE / "public_tests"
HIDDEN_TESTS = FIXTURE / "hidden_tests"
VERIFIER_DIR = REPOSITORY_ROOT / "docker" / "verifier"
ANALYSIS_DIR = REPOSITORY_ROOT / "docker" / "analysis-worker"
PROXY_DIR = REPOSITORY_ROOT / "docker" / "range-proxy"

CASE_ID = "AGE-0002"
TARGET_REF = "service://object-auth-range"
NETWORK = "aegis-object-auth-case-net"
APP_NAME = "aegis-object-auth-case-app"
PROXY_NAME = "aegis-object-auth-case-proxy"
TEST_BOB_TOKEN = "test-token-bob"
TEST_ALICE_TOKEN = "test-token-alice"
ALLOWED_FILES = frozenset({"app.py"})
ORIGINAL_SOURCE = (SOURCE / "app.py").read_text(encoding="utf-8")
FIXED_SOURCE = ORIGINAL_SOURCE.replace(
    '    # VULNERABLE: the authenticated principal is never compared with document["owner"].\n',
    '    if document["owner"] != g.principal:\n        abort(404)\n',
)


def _build_image(directory: Path, tag: str) -> str:
    subprocess.run(
        ["docker", "build", "--tag", tag, "--file", str(directory / "Dockerfile"), str(directory)],
        check=True,
        capture_output=True,
        text=True,
        timeout=600,
    )
    inspected = subprocess.run(
        ["docker", "inspect", tag, "--format={{.Id}}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return inspected.stdout.strip()


def _diff(updated: str) -> str:
    return "".join(
        difflib.unified_diff(
            ORIGINAL_SOURCE.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile="a/app.py",
            tofile="b/app.py",
        )
    )


@pytest.mark.parametrize("denial_status", [403, 404])
def test_object_authorization_incident_runs_through_brokered_defense(
    docker_available: bool,
    analysis_worker_image_id: str,
    tmp_path: Path,
    denial_status: int,
) -> None:
    _run_object_authorization_case(
        docker_available, analysis_worker_image_id, tmp_path, denial_status=denial_status
    )


@pytest.mark.skipif(
    os.environ.get("AEGIS_LIVE_MODEL_REPAIR") != "1"
    or not (os.environ.get("LLM_URL") and os.environ.get("LLM_API_KEY")),
    reason="set AEGIS_LIVE_MODEL_REPAIR=1 and model credentials for full model repair",
)
def test_object_authorization_case_with_live_model_reasoning_and_repair(
    docker_available: bool, analysis_worker_image_id: str, tmp_path: Path
) -> None:
    endpoint = os.environ["LLM_URL"].rstrip("/")
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        pytest.fail("refusing to send credentials to non-local plaintext HTTP")
    if not endpoint.endswith("/v1"):
        endpoint += "/v1"
    config = HostedProviderConfig(
        base_url=endpoint,
        model=os.environ.get("LLM_MODEL", "qwen38"),
        reasoning_effort="none",
        timeout_seconds=180,
        max_repair_attempts=0,
    )
    patch_provider = HostedPatchProvider(
        config,
        api_key=os.environ["LLM_API_KEY"],
        structured_output=os.environ.get("AEGIS_MODEL_JSON_SCHEMA") == "1",
        public_syntax_retry=os.environ.get("AEGIS_PUBLIC_SYNTAX_RETRY") == "1",
    )
    patch_request = PatchGenerationRequest(
        case_id=CASE_ID,
        base_repository="object-authorization-v1",
        base_source_digest=hash_source_tree(str(SOURCE)),
        source_file="app.py",
        source=ORIGINAL_SOURCE,
        vulnerability_summary=(
            "The document endpoint authenticates a synthetic principal but returns any "
            "existing document without comparing the document owner with that principal. "
            "Deny cross-owner access while preserving owner access and invalid-token behavior."
        ),
        allowed_files=ALLOWED_FILES,
    )
    report_path = (
        REPOSITORY_ROOT
        / "artifacts"
        / "benchmark_runs"
        / f"live-object-auth-case-{uuid4().hex}.json"
    )
    _run_object_authorization_case(
        docker_available,
        analysis_worker_image_id,
        tmp_path,
        reasoning_provider=HostedOpenAICompatibleProvider(
            config, api_key=os.environ["LLM_API_KEY"]
        ),
        patch_generator=lambda: patch_provider.generate(patch_request),
        report_path=report_path,
        model=config.model,
    )


def _run_object_authorization_case(
    docker_available: bool,
    analysis_worker_image_id: str,
    tmp_path: Path,
    *,
    reasoning_provider: ReasoningProvider | None = None,
    patch_generator: Callable[[], PatchCandidate] | None = None,
    report_path: Path | None = None,
    model: str | None = None,
    denial_status: int = 404,
) -> None:
    started_at = datetime.now(UTC)
    started = time.perf_counter()
    if not docker_available:
        pytest.skip("Docker is not available")
    if FIXED_SOURCE == ORIGINAL_SOURCE:
        pytest.fail("fixture changed; review the expected authorization repair")

    app_image = _build_image(FIXTURE, "aegis-object-auth-case:base")
    proxy_image = _build_image(PROXY_DIR, "aegis-object-auth-case:proxy")
    verifier_image = _build_image(VERIFIER_DIR, "aegis-object-auth-case:verifier")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rules_file = rules_dir / "rules.json"
    write_rules(str(rules_file), ContainmentRule())

    stop_service(APP_NAME)
    stop_service(PROXY_NAME)
    remove_network(NETWORK)
    create_network(NETWORK)
    try:
        start_service(ServiceSpec(image=app_image, name=APP_NAME, network=NETWORK))
        start_service(
            ServiceSpec(
                image=proxy_image,
                name=PROXY_NAME,
                network=NETWORK,
                env={"AEGIS_BACKEND_URL": f"http://{APP_NAME}:8080"},
                volumes=((str(rules_dir), "/rules", "ro"),),
            )
        )
        base_url = f"http://{container_ip(PROXY_NAME)}:8081"
        _wait_ready(base_url)

        def request_alice_document() -> int:
            return send_get(
                base_url,
                "/documents/doc-alice",
                headers={"Authorization": f"Bearer {TEST_ALICE_TOKEN}"},
            ).status_code

        def request_cross_owner() -> int:
            return send_get(
                base_url,
                "/documents/doc-alice",
                headers={"Authorization": f"Bearer {TEST_BOB_TOKEN}"},
            ).status_code

        assert request_cross_owner() == 200, "vulnerable baseline must reproduce the flaw"
        assert request_alice_document() == 200

        now = datetime.now(UTC)
        scope = ScopePolicy(
            case_id=CASE_ID,
            version=1,
            authorization=Authorization(expires_at=now + timedelta(hours=1)),
            targets=Targets(services=(ServiceTarget(id="object-auth-range", network=NETWORK),)),
            network=NetworkPolicy(),
            filesystem=FilesystemPolicy(),
            tools=ToolsPolicy(
                allow=("range.proxy", "range.deployment", "semgrep.scan", "range.proxy.logs")
            ),
            actions=ActionsPolicy(
                auto=("scan.run", "telemetry.read"),
                approval=(
                    "contain.rate_limit",
                    "contain.rollback",
                    "deployment.rollout",
                    "deployment.rollback",
                ),
                deny=("host.shell", "iam.admin", "audit.modify"),
            ),
            budgets=Budgets(
                tool_calls=40, model_tokens=50_000, wall_time_seconds=1800, spend_usd=10
            ),
        )
        case = Case(
            id=CASE_ID,
            title="Synthetic object-authorization incident",
            created_at=now,
            created_by="operator:test",
            scope_ref=f"scope://{CASE_ID}/1",
            scope_digest=sha256_digest(scope.model_dump_json().encode()),
        )
        registry = AdapterRegistry()
        registry.register(
            ProxyRuleAdapter(
                str(rules_file),
                deny_query_patterns=(),
                deny_authorization_patterns=(r"^Bearer test-token-bob$",),
                rule_set_id="revoke-synthetic-bob-session",
            )
        )
        registry.register(ProxyLogsAdapter(container_name=PROXY_NAME, target_ref=TARGET_REF))
        artifacts = InMemoryArtifactStore()
        registry.register(
            make_range_semgrep_adapter(
                artifacts=artifacts,
                fixture_dir=FIXTURE,
                analysis_image=analysis_worker_image_id,
            )
        )
        registry.register(
            RangeDeploymentAdapter(
                fixture_dir=str(FIXTURE),
                source_subdirectory="src",
                allowed_files=ALLOWED_FILES,
                base_source_digest=hash_source_tree(str(SOURCE)),
                base_image=app_image,
                service=ServiceSpec(image=app_image, name=APP_NAME, network=NETWORK),
                target_ref=TARGET_REF,
                rules_file=str(rules_file),
                readiness_probe=lambda: (
                    send_get(base_url, "/healthz", timeout=1).status_code == 200
                ),
            )
        )
        audit = InMemoryAuditSink()
        broker = ActionBroker(registry=registry, audit=audit, artifacts=artifacts)

        def approval(request: ActionRequest) -> Approval:
            return Approval(
                id=f"approval-{request.id}",
                case_id=request.case_id,
                subject_ref=f"action-request://{request.case_id}/{request.id}",
                requested_at=request.requested_at,
                expires_at=request.requested_at + timedelta(minutes=5),
                decision=ApprovalDecision.APPROVED,
                decided_by="operator:test",
                decided_at=request.requested_at,
            )

        actions = BrokeredDefenderActions(
            coordinator=ActionTransactionCoordinator(broker),
            case=case,
            scope=scope,
            approval_provider=approval,
            policy_version="object-auth-range-v1",
            clock=lambda: now,
        )
        investigator = RangeEvidenceInvestigator(
            registry=registry,
            broker=broker,
            case=case,
            scope=scope,
            artifacts=artifacts,
            fixture_dir=FIXTURE,
            source_dir=SOURCE,
            app_image=app_image,
            app_container=APP_NAME,
            target_ref=TARGET_REF,
            now=now,
            route_source_bindings=(
                RouteSourceBinding(route_prefix="/documents", source_file="app.py"),
            ),
        )

        fixed_source = FIXED_SOURCE.replace(
            'if document["owner"] != g.principal:\n        abort(404)',
            f'if document["owner"] != g.principal:\n        abort({denial_status})',
        )
        diff = _diff(fixed_source)
        candidate = PatchCandidate(
            id="object-auth-case-oracle-candidate",
            case_id=CASE_ID,
            base_repository="object-authorization-v1",
            base_source_digest=hash_source_tree(str(SOURCE)),
            diff=diff,
            diff_digest=Digest(digest=hashlib.sha256(diff.encode()).hexdigest()),
            files_changed=changed_files(diff),
            root_cause="The endpoint returns documents without checking their owner.",
            repair_invariant="Only the authenticated owner may read a document.",
            generated_at=now,
        )

        generated_candidates: list[PatchCandidate] = []
        verification_checks: list[CheckResult] = []

        def generate_candidate() -> PatchCandidate:
            generated = patch_generator() if patch_generator is not None else candidate
            generated_candidates.append(generated)
            return generated

        def verify_candidate(patch: PatchCandidate) -> AssuranceOutcome:
            checks = [
                check_source_integrity(patch, trusted_source_dir=str(SOURCE)),
                check_diff_policy(patch, allowed_files=ALLOWED_FILES),
            ]
            with tempfile.TemporaryDirectory(prefix="aegis-object-auth-case-") as temp:
                diff_file = Path(temp) / "candidate.diff"
                diff_file.write_text(patch.diff, encoding="utf-8")
                checks.extend(
                    check_clean_room_tests(
                        image_ref=verifier_image,
                        trusted_source_dir=str(SOURCE),
                        diff_file=str(diff_file),
                        public_tests_dir=str(PUBLIC_TESTS),
                        hidden_tests_dir=str(HIDDEN_TESTS),
                    )
                )
            verification_checks.extend(checks)
            return evaluate_assurance(tuple(checks))

        proposal = StructuredProposal(
            kind="propose_action",
            rationale="Revoke the synthetic Bob session suspected in the object-access event.",
            action={
                "action_type": "contain.rate_limit",
                "target_ref": TARGET_REF,
                "adapter": "range.proxy",
                "reason": "Temporarily block the synthetic Bob bearer token in this range.",
            },
        )
        trace = run_case(
            CASE_ID,
            CaseDependencies(
                provider=reasoning_provider or StubProvider(response=proposal),
                exploit_reachable=lambda: request_cross_owner() == 200,
                attack_blocked=lambda: request_cross_owner() == 403,
                benign_available=lambda: request_alice_document() == 200,
                brokered_actions=actions,
                generate_candidate=generate_candidate,
                verify_candidate=verify_candidate,
                deployment_target_ref=TARGET_REF,
                recovery_attack_blocked=lambda: request_cross_owner() in {403, 404},
                recovery_benign_available=lambda: request_alice_document() == 200,
                investigate=investigator,
                incident_summary=(
                    "Synthetic Bob authenticated to a document belonging to Alice; "
                    "investigate possible broken object-level authorization."
                ),
                containment_tools=(
                    ToolDescriptor(
                        id="range.proxy",
                        category="local range containment",
                        risk_tier=RiskTier.R3_REVERSIBLE_RESPONSE,
                        description=(
                            "Supports action_type=contain.rate_limit, "
                            "target_ref=service://object-auth-range, adapter=range.proxy, "
                            "with empty parameters. Applies owner-configured reversible "
                            "containment in this range."
                        ),
                    ),
                ),
                max_containment_attempts=1,
                max_repair_attempts=1,
            ),
        )

        if report_path is not None:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report = {
                "benchmark": "Aegis Layer-0 synthetic incident-to-recovery integration",
                "not_a_standard_benchmark": True,
                "scenario": "object-authorization-v1",
                "model": model,
                "repository_revision": subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=REPOSITORY_ROOT,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                ).stdout.strip(),
                "working_tree_dirty": bool(
                    subprocess.run(
                        ["git", "status", "--porcelain"],
                        cwd=REPOSITORY_ROOT,
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    ).stdout.strip()
                ),
                "policy_digest": case.scope_digest.model_dump(mode="json"),
                "policy_version": "object-auth-range-v1",
                "patch_prompt_version": "full-source-v2" if patch_generator is not None else None,
                "json_schema_requested": os.environ.get("AEGIS_MODEL_JSON_SCHEMA") == "1",
                "public_syntax_retry_enabled": os.environ.get("AEGIS_PUBLIC_SYNTAX_RETRY") == "1",
                "started_at": started_at.isoformat(),
                "duration_seconds": round(time.perf_counter() - started, 3),
                "prepared_patch_used": patch_generator is None,
                "approval_mode": "synthetic-test-operator",
                "base_source_digest": hash_source_tree(str(SOURCE)).model_dump(mode="json"),
                "images": {"app": app_image, "proxy": proxy_image, "verifier": verifier_image},
                "trace": {
                    "states": [state.value for state in trace.states],
                    "notes": trace.notes,
                    "halted": trace.halted,
                    "halt_reason": trace.halt_reason,
                    "final_state": trace.final_state.value,
                },
                "candidates": [item.model_dump(mode="json") for item in generated_candidates],
                "verification": [item.model_dump(mode="json") for item in verification_checks],
                "audit": [item.model_dump(mode="json") for item in audit.events_for_case(CASE_ID)],
            }
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(f"Live synthetic case record: {report_path}")
        assert not trace.halted, (trace.halt_reason, trace.notes)
        assert trace.final_state is CaseState.CLOSED
        assert trace.investigation is not None
        assert any(
            item.source_file == "app.py"
            and item.finding_rule_id.endswith("python-flask-object-authorization")
            for item in trace.investigation.hypotheses
        )
        assert request_cross_owner() in {403, 404}
        assert request_alice_document() == 200
        assert TEST_BOB_TOKEN not in container_logs(PROXY_NAME)
        events = audit.events_for_case(CASE_ID)
        assert AuditEventType.APPROVAL_RECORDED in [event.event_type for event in events]
        assert any("action_type=deployment.rollout" in event.summary for event in events)
        assert broker.audit_root(CASE_ID) is not None
        if patch_generator is not None:
            assert len(generated_candidates) == 1
            assert generated_candidates[0].id != "object-auth-case-oracle-candidate"
    finally:
        stop_service(APP_NAME)
        stop_service(PROXY_NAME)
        remove_network(NETWORK)


def _wait_ready(base_url: str, *, attempts: int = 20) -> None:
    for _ in range(attempts):
        if send_get(base_url, "/healthz", timeout=1.0).status_code == 200:
            return
        time.sleep(0.5)
    raise RuntimeError("object-authorization range did not become ready")
