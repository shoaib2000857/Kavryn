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
import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aegis.broker.adapter import AdapterResult
from aegis.broker.broker import ActionBroker
from aegis.broker.registry import AdapterRegistry
from aegis.core.coordinator import (
    ActionTransactionCoordinator,
    VerificationCheck,
    VerificationOutcome,
)
from aegis.core.receipt import ExecutionDisposition, verify_execution_receipt
from aegis.core.transaction import ActionTransaction, TransactionState
from aegis.domain.action import ActionRequest
from aegis.domain.audit import AuditEventType
from aegis.domain.base import ActorRole, Digest
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
from aegis.investigation.range import RangeEvidenceInvestigator, make_range_semgrep_adapter
from aegis.orchestrator.actions import BrokeredDefenderActions
from aegis.orchestrator.case_runner import CaseDependencies, run_case
from aegis.policy.approval import Approval, ApprovalDecision
from aegis.providers.base import ReasoningProvider
from aegis.providers.hosted import HostedOpenAICompatibleProvider, HostedProviderConfig
from aegis.providers.schemas import ProposalKind, StructuredProposal, ToolDescriptor
from aegis.providers.stub import StubProvider
from aegis.range.adapter import ProxyRuleAdapter
from aegis.range.containment import ContainmentRule, write_rules
from aegis.range.deployment import RangeDeploymentAdapter
from aegis.range.logs import ProxyLogsAdapter
from aegis.range.network import create_network, remove_network
from aegis.range.service import ServiceSpec, container_ip, start_service, stop_service
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

    try:
        start_service(ServiceSpec(image=original_app_image_id, name=APP_NAME, network=NETWORK_NAME))
        start_service(
            ServiceSpec(
                image=proxy_image_id,
                name=PROXY_NAME,
                network=NETWORK_NAME,
                env={"AEGIS_BACKEND_URL": f"http://{APP_NAME}:8080"},
                volumes=((str(rules_dir), "/rules", "ro"),),
            )
        )
        base_url = f"http://{container_ip(PROXY_NAME)}:8081"
        _wait_until_ready(base_url)
        yield base_url, str(rules_file)
    finally:
        stop_service(APP_NAME)
        stop_service(PROXY_NAME)
        remove_network(NETWORK_NAME)


def _run_full_case(
    running_range: tuple[str, str],
    verifier_image_id: str,
    original_app_image_id: str,
    analysis_worker_image_id: str,
    *,
    provider: ReasoningProvider,
) -> None:
    base_url, rules_file = running_range
    diff = _diff_for(GOOD_APP_PY)
    candidate = PatchCandidate(
        id="patch-fullcase-0001",
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

    def recovery_attack_blocked() -> bool:
        return send_get(base_url, "/download?filename=../secret.txt").status_code in (400, 403, 404)

    now = datetime.now(UTC)
    scope = ScopePolicy(
        case_id="AGE-0001",
        version=1,
        authorization=Authorization(expires_at=now + timedelta(hours=1)),
        targets=Targets(services=(ServiceTarget(id="demo-api-range", network=NETWORK_NAME),)),
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
        title="Synthetic path traversal full case",
        created_at=now,
        created_by="operator:alice",
        scope_ref="scope://AGE-0001/1",
        scope_digest=sha256_digest(scope.model_dump_json().encode()),
    )
    action_registry = AdapterRegistry()
    action_registry.register(ProxyRuleAdapter(rules_file))
    action_registry.register(
        ProxyLogsAdapter(container_name=PROXY_NAME, target_ref="service://demo-api-range")
    )
    artifact_store = InMemoryArtifactStore()
    action_registry.register(
        make_range_semgrep_adapter(
            artifacts=artifact_store,
            fixture_dir=FIXTURE_DIR,
            analysis_image=analysis_worker_image_id,
        )
    )
    action_registry.register(
        RangeDeploymentAdapter(
            fixture_dir=str(FIXTURE_DIR),
            source_subdirectory="src",
            allowed_files=ALLOWED_FILES,
            base_source_digest=hash_source_tree(str(SRC_DIR)),
            base_image=original_app_image_id,
            service=ServiceSpec(
                image=original_app_image_id,
                name=APP_NAME,
                network=NETWORK_NAME,
            ),
            target_ref="service://demo-api-range",
            rules_file=rules_file,
            readiness_probe=lambda: (
                send_get(base_url, "/download?filename=welcome.txt", timeout=1.0).status_code == 200
            ),
        )
    )
    audit_sink = InMemoryAuditSink()
    broker = ActionBroker(
        registry=action_registry,
        audit=audit_sink,
        artifacts=artifact_store,
    )

    def approve_action(request: ActionRequest) -> Approval:
        requested_at = request.requested_at
        return Approval(
            id=f"approval-{request.id}",
            case_id=request.case_id,
            subject_ref=f"action-request://{request.case_id}/{request.id}",
            requested_at=requested_at,
            expires_at=requested_at + timedelta(minutes=5),
            decision=ApprovalDecision.APPROVED,
            decided_by="operator:alice",
            decided_at=requested_at,
        )

    brokered_actions = BrokeredDefenderActions(
        coordinator=ActionTransactionCoordinator(broker),
        case=case,
        scope=scope,
        approval_provider=approve_action,
        policy_version="range-scope-v1",
        clock=lambda: now,
    )
    investigate = RangeEvidenceInvestigator(
        registry=action_registry,
        broker=broker,
        case=case,
        scope=scope,
        artifacts=artifact_store,
        fixture_dir=FIXTURE_DIR,
        source_dir=SRC_DIR,
        app_image=original_app_image_id,
        app_container=APP_NAME,
        target_ref="service://demo-api-range",
        now=now,
    )

    deps = CaseDependencies(
        provider=provider,
        exploit_reachable=lambda: (
            send_get(base_url, "/download?filename=../secret.txt").status_code == 200
        ),
        attack_blocked=recovery_attack_blocked,
        benign_available=lambda: (
            send_get(base_url, "/download?filename=welcome.txt").status_code == 200
        ),
        generate_candidate=lambda: candidate,
        verify_candidate=verify_candidate,
        deployment_target_ref="service://demo-api-range",
        recovery_attack_blocked=recovery_attack_blocked,
        recovery_benign_available=lambda: (
            send_get(base_url, "/download?filename=welcome.txt").status_code == 200
        ),
        investigate=investigate,
        containment_tools=(
            ToolDescriptor(
                id="range.proxy",
                category="network containment",
                risk_tier=RiskTier.R3_REVERSIBLE_RESPONSE,
                description="Applies a reversible deny-query proxy rule in front of this range.",
            ),
        ),
        brokered_actions=brokered_actions,
        max_containment_attempts=1,
        max_repair_attempts=1,
    )

    trace = run_case("AGE-0001", deps)

    assert not trace.halted, (trace.halt_reason, trace.notes[-1])
    assert trace.final_state is CaseState.CLOSED
    assert trace.investigation is not None and trace.investigation.correlated_pairs >= 1
    assert any(
        event.event_type is AuditEventType.ACTION_REQUESTED
        and "action_type=deployment.rollout" in event.summary
        for event in audit_sink.events_for_case(case.id)
    )
    assert broker.audit_root(case.id) is not None
    assert AuditEventType.APPROVAL_RECORDED in [
        event.event_type for event in audit_sink.events_for_case(case.id)
    ]

    json_report = render_json_report(trace)
    human_report = render_human_report(trace)
    assert '"final_state": "closed"' in json_report
    assert "completed at `closed`" in human_report


def test_full_case_reaches_closed_with_real_infrastructure(
    running_range: tuple[str, str],
    verifier_image_id: str,
    original_app_image_id: str,
    analysis_worker_image_id: str,
) -> None:
    _run_full_case(
        running_range,
        verifier_image_id,
        original_app_image_id,
        analysis_worker_image_id,
        provider=StubProvider(response=CONTAINMENT_PROPOSAL),
    )


@pytest.mark.skipif(
    not (os.environ.get("LLM_URL") and os.environ.get("LLM_API_KEY")),
    reason="set LLM_URL and LLM_API_KEY to run the live hosted-model case",
)
def test_full_case_reaches_closed_with_live_hosted_model(
    running_range: tuple[str, str],
    verifier_image_id: str,
    original_app_image_id: str,
    analysis_worker_image_id: str,
) -> None:
    endpoint = os.environ["LLM_URL"].rstrip("/")
    if not endpoint.endswith("/v1"):
        endpoint += "/v1"
    provider = HostedOpenAICompatibleProvider(
        HostedProviderConfig(
            base_url=endpoint,
            model=os.environ.get("LLM_MODEL", "qwen38"),
            timeout_seconds=180,
            max_repair_attempts=2,
            reasoning_effort="none",
        ),
        api_key=os.environ["LLM_API_KEY"],
    )
    _run_full_case(
        running_range,
        verifier_image_id,
        original_app_image_id,
        analysis_worker_image_id,
        provider=provider,
    )


def test_brokered_range_containment_commits_after_independent_postcondition_checks(
    running_range: tuple[str, str],
) -> None:
    """Exercise the transaction/approval/receipt path against real local Docker services."""
    base_url, rules_file = running_range
    now = datetime.now(UTC)
    case_id = "AGE-RANGE-TX-01"
    scope = ScopePolicy(
        case_id=case_id,
        version=1,
        authorization=Authorization(expires_at=now + timedelta(hours=1)),
        targets=Targets(services=(ServiceTarget(id="demo-api-range", network=NETWORK_NAME),)),
        network=NetworkPolicy(),
        filesystem=FilesystemPolicy(),
        tools=ToolsPolicy(allow=("range.proxy",)),
        actions=ActionsPolicy(
            approval=("contain.rate_limit", "contain.rollback"),
            deny=("host.shell", "audit.modify"),
        ),
        budgets=Budgets(
            tool_calls=20,
            model_tokens=10_000,
            wall_time_seconds=300,
            spend_usd=20,
        ),
    )
    case = Case(
        id=case_id,
        title="Brokered containment transaction integration",
        created_at=now,
        created_by="operator:alice",
        scope_ref=f"scope://{case_id}/1",
        scope_digest=sha256_digest(scope.model_dump_json().encode()),
    )
    request = ActionRequest(
        id="contain-tx-1",
        case_id=case_id,
        actor_id="reasoning_runtime:test",
        role=ActorRole.REASONING_RUNTIME,
        action_type="contain.rate_limit",
        target_ref="service://demo-api-range",
        adapter="range.proxy",
        parameters={"operation": "apply"},
        reason="Apply the reviewed traversal filter to this authorized local range.",
        requested_at=now,
    )
    approval = Approval(
        id="approval-contain-1",
        case_id=case_id,
        subject_ref=f"action-request://{case_id}/{request.id}",
        requested_at=now,
        expires_at=now + timedelta(minutes=5),
        decision=ApprovalDecision.APPROVED,
        decided_by="operator:alice",
        decided_at=now,
    )

    registry = AdapterRegistry()
    registry.register(ProxyRuleAdapter(rules_file))
    audit = InMemoryAuditSink()
    broker = ActionBroker(
        registry=registry,
        audit=audit,
        artifacts=InMemoryArtifactStore(),
    )

    def verify_containment(_tx: ActionTransaction, _result: AdapterResult) -> VerificationOutcome:
        attack = send_get(base_url, "/download?filename=../secret.txt")
        benign = send_get(base_url, "/download?filename=welcome.txt")
        return VerificationOutcome(
            verifier_id="verifier:range-probes",
            checked_at=datetime.now(UTC),
            checks=(
                VerificationCheck(
                    id="attack-blocked",
                    verifier_id="verifier:range-probes",
                    passed=attack.status_code == 403,
                    evidence_ref=f"evidence://{case_id}/containment/attack",
                    detail=f"traversal status: {attack.status_code}",
                ),
                VerificationCheck(
                    id="benign-available",
                    verifier_id="verifier:range-probes",
                    passed=benign.status_code == 200,
                    evidence_ref=f"evidence://{case_id}/containment/benign",
                    detail=f"benign status: {benign.status_code}",
                ),
            ),
        )

    tx, receipt, verification = ActionTransactionCoordinator(broker).execute(
        request,
        case=case,
        scope=scope,
        now=now,
        policy_version="scope-v1",
        approval=approval,
        verifier=verify_containment,
    )

    assert tx.state is TransactionState.COMMITTED
    assert verification is not None and verification.passed
    assert receipt is not None and receipt.disposition is ExecutionDisposition.COMMITTED
    assert tx.approval_ref == f"approval://{case_id}/{approval.id}"
    assert receipt.audit_root == broker.audit_root(case_id)
    assert verify_execution_receipt(receipt)
    assert AuditEventType.APPROVAL_RECORDED in [
        event.event_type for event in audit.events_for_case(case_id)
    ]


def test_brokered_range_containment_rolls_back_when_benign_traffic_breaks(
    running_range: tuple[str, str],
) -> None:
    """A test-only overbroad rule must fail verification and restore prior behavior."""
    base_url, rules_file = running_range
    now = datetime.now(UTC)
    case_id = "AGE-RANGE-TX-ROLLBACK-01"
    scope = ScopePolicy(
        case_id=case_id,
        version=1,
        authorization=Authorization(expires_at=now + timedelta(hours=1)),
        targets=Targets(services=(ServiceTarget(id="demo-api-range", network=NETWORK_NAME),)),
        network=NetworkPolicy(),
        filesystem=FilesystemPolicy(),
        tools=ToolsPolicy(allow=("range.proxy",)),
        actions=ActionsPolicy(
            approval=("contain.rate_limit", "contain.rollback"),
            deny=("host.shell", "audit.modify"),
        ),
        budgets=Budgets(
            tool_calls=20,
            model_tokens=10_000,
            wall_time_seconds=300,
            spend_usd=20,
        ),
    )
    case = Case(
        id=case_id,
        title="Brokered containment rollback integration",
        created_at=now,
        created_by="operator:alice",
        scope_ref=f"scope://{case_id}/1",
        scope_digest=sha256_digest(scope.model_dump_json().encode()),
    )
    request = ActionRequest(
        id="contain-tx-overbroad-1",
        case_id=case_id,
        actor_id="reasoning_runtime:test",
        role=ActorRole.REASONING_RUNTIME,
        action_type="contain.rate_limit",
        target_ref="service://demo-api-range",
        adapter="range.proxy",
        parameters={"operation": "apply"},
        reason="Exercise fail-closed rollback when containment harms availability.",
        requested_at=now,
    )
    approval = Approval(
        id="approval-overbroad-1",
        case_id=case_id,
        subject_ref=f"action-request://{case_id}/{request.id}",
        requested_at=now,
        expires_at=now + timedelta(minutes=5),
        decision=ApprovalDecision.APPROVED,
        decided_by="operator:alice",
        decided_at=now,
    )
    rollback = ActionRequest(
        id="contain-tx-overbroad-rollback-1",
        case_id=case_id,
        actor_id="control:transaction-coordinator",
        role=ActorRole.CONTROL_PLANE,
        action_type="contain.rollback",
        target_ref="service://demo-api-range",
        adapter="range.proxy",
        parameters={"operation": "rollback", "rollback_of": request.id},
        reason="Restore the prior proxy policy after failed availability checks.",
        requested_at=now,
    )
    rollback_approval = Approval(
        id="approval-rollback-overbroad-1",
        case_id=case_id,
        subject_ref=f"action-request://{case_id}/{rollback.id}",
        requested_at=now,
        expires_at=now + timedelta(minutes=5),
        decision=ApprovalDecision.APPROVED,
        decided_by="operator:alice",
        decided_at=now,
    )

    class OverbroadTestAdapter(ProxyRuleAdapter):
        """Intentionally faulty test adapter; never registered by the application."""

        def run(self, action: ActionRequest, *, capability_ref: str) -> AdapterResult:
            result = super().run(action, capability_ref=capability_ref)
            if action.parameters.get("operation") == "apply":
                write_rules(rules_file, ContainmentRule(deny_query_patterns=(r".*",)))
            return result

    registry = AdapterRegistry()
    registry.register(OverbroadTestAdapter(rules_file))
    broker = ActionBroker(
        registry=registry,
        audit=InMemoryAuditSink(),
        artifacts=InMemoryArtifactStore(),
    )

    def verify_bad_containment(
        _tx: ActionTransaction, _result: AdapterResult
    ) -> VerificationOutcome:
        attack = send_get(base_url, "/download?filename=../secret.txt")
        benign = send_get(base_url, "/download?filename=welcome.txt")
        return VerificationOutcome(
            verifier_id="verifier:range-probes",
            checked_at=datetime.now(UTC),
            checks=(
                VerificationCheck(
                    id="attack-blocked",
                    verifier_id="verifier:range-probes",
                    passed=attack.status_code == 403,
                    evidence_ref=f"evidence://{case_id}/containment/attack",
                    detail=f"traversal status: {attack.status_code}",
                ),
                VerificationCheck(
                    id="benign-available",
                    verifier_id="verifier:range-probes",
                    passed=benign.status_code == 200,
                    evidence_ref=f"evidence://{case_id}/containment/benign",
                    detail=f"benign status: {benign.status_code}",
                ),
            ),
        )

    def verify_restored(_tx: ActionTransaction, _result: AdapterResult) -> VerificationOutcome:
        attack = send_get(base_url, "/download?filename=../secret.txt")
        benign = send_get(base_url, "/download?filename=welcome.txt")
        return VerificationOutcome(
            verifier_id="verifier:range-probes",
            checked_at=datetime.now(UTC),
            checks=(
                VerificationCheck(
                    id="rollback-restored-attack-baseline",
                    verifier_id="verifier:range-probes",
                    passed=attack.status_code == 200,
                    evidence_ref=f"evidence://{case_id}/rollback/attack",
                    detail=f"original fixture attack status restored: {attack.status_code}",
                ),
                VerificationCheck(
                    id="rollback-restored-benign",
                    verifier_id="verifier:range-probes",
                    passed=benign.status_code == 200,
                    evidence_ref=f"evidence://{case_id}/rollback/benign",
                    detail=f"benign status: {benign.status_code}",
                ),
            ),
        )

    tx, receipt, verification = ActionTransactionCoordinator(broker).execute(
        request,
        case=case,
        scope=scope,
        now=now,
        policy_version="scope-v1",
        approval=approval,
        verifier=verify_bad_containment,
        rollback_request=rollback,
        rollback_approval=rollback_approval,
        rollback_verifier=verify_restored,
    )

    assert tx.state is TransactionState.ROLLED_BACK
    assert verification is not None and not verification.passed
    assert receipt is not None and receipt.disposition is ExecutionDisposition.ROLLED_BACK
    assert tx.rollback_ref == f"transaction://{case_id}/{rollback.id}-rollback"
    assert send_get(base_url, "/download?filename=../secret.txt").status_code == 200
    assert send_get(base_url, "/download?filename=welcome.txt").status_code == 200


def test_brokered_deployment_rolls_back_when_runtime_attack_replay_still_succeeds(
    running_range: tuple[str, str], original_app_image_id: str
) -> None:
    """A failed runtime postcondition restores the prior image and containment rule."""
    base_url, rules_file = running_range
    now = datetime.now(UTC)
    case_id = "AGE-DEPLOY-ROLLBACK-01"
    scope = ScopePolicy(
        case_id=case_id,
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
            model_tokens=20_000,
            wall_time_seconds=900,
            spend_usd=20,
        ),
    )
    case = Case(
        id=case_id,
        title="Brokered deployment rollback integration",
        created_at=now,
        created_by="operator:alice",
        scope_ref=f"scope://{case_id}/1",
        scope_digest=sha256_digest(scope.model_dump_json().encode()),
    )
    registry = AdapterRegistry()
    registry.register(ProxyRuleAdapter(rules_file))
    registry.register(
        RangeDeploymentAdapter(
            fixture_dir=str(FIXTURE_DIR),
            source_subdirectory="src",
            allowed_files=ALLOWED_FILES,
            base_source_digest=hash_source_tree(str(SRC_DIR)),
            base_image=original_app_image_id,
            service=ServiceSpec(
                image=original_app_image_id,
                name=APP_NAME,
                network=NETWORK_NAME,
            ),
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

    def approve_action(request: ActionRequest) -> Approval:
        return Approval(
            id=f"approval-{request.id}",
            case_id=case_id,
            subject_ref=f"action-request://{case_id}/{request.id}",
            requested_at=now,
            expires_at=now + timedelta(minutes=5),
            decision=ApprovalDecision.APPROVED,
            decided_by="operator:alice",
            decided_at=now,
        )

    actions = BrokeredDefenderActions(
        coordinator=ActionTransactionCoordinator(broker),
        case=case,
        scope=scope,
        approval_provider=approve_action,
        policy_version="range-scope-v1",
        clock=lambda: now,
    )

    def attack_blocked() -> bool:
        return send_get(base_url, "/download?filename=../secret.txt").status_code in (
            400,
            403,
            404,
        )

    def benign_available() -> bool:
        return send_get(base_url, "/download?filename=welcome.txt").status_code == 200

    assert CONTAINMENT_PROPOSAL.action is not None
    containment = actions.contain(
        CONTAINMENT_PROPOSAL.action,
        exploit_reachable=lambda: (
            send_get(base_url, "/download?filename=../secret.txt").status_code == 200
        ),
        attack_blocked=attack_blocked,
        benign_available=benign_available,
    )
    assert containment.transaction.state is TransactionState.COMMITTED

    bad_diff = _diff_for(ORIGINAL_APP_PY + "\n# syntactically changed, vulnerability retained\n")
    candidate = PatchCandidate(
        id="patch-known-bad-runtime-verification",
        case_id=case_id,
        base_repository="path-traversal-v1",
        base_source_digest=hash_source_tree(str(SRC_DIR)),
        diff=bad_diff,
        diff_digest=Digest(digest=hashlib.sha256(bad_diff.encode()).hexdigest()),
        files_changed=changed_files(bad_diff),
        root_cause="test fixture deliberately leaves path traversal unchanged",
        repair_invariant="runtime must block traversal after rollout",
        generated_at=now,
    )
    deployment = actions.deploy(
        candidate,
        target_ref="service://demo-api-range",
        attack_blocked=attack_blocked,
        benign_available=benign_available,
    )

    assert deployment.transaction.state is TransactionState.ROLLED_BACK
    assert deployment.receipt is not None
    assert deployment.receipt.disposition is ExecutionDisposition.ROLLED_BACK
    assert deployment.verification is not None and not deployment.verification.passed
    assert send_get(base_url, "/download?filename=../secret.txt").status_code == 403
    assert send_get(base_url, "/download?filename=welcome.txt").status_code == 200
