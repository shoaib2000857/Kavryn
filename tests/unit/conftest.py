from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from aegis.broker.adapter import AdapterDescriptor, AdapterLimits, AdapterPermissions
from aegis.broker.broker import ActionBroker
from aegis.broker.mock import MockAdapter
from aegis.broker.registry import AdapterRegistry
from aegis.core.coordinator import ActionTransactionCoordinator
from aegis.domain import (
    ActionsPolicy,
    Authorization,
    Budgets,
    Case,
    Digest,
    FilesystemPolicy,
    NetworkPolicy,
    RepositoryTarget,
    ScopePolicy,
    ServiceTarget,
    Targets,
    ToolsPolicy,
)
from aegis.domain.action import ActionRequest
from aegis.domain.policy import RiskTier
from aegis.evidence.audit import InMemoryAuditSink
from aegis.evidence.store import InMemoryArtifactStore, sha256_digest
from aegis.investigation.correlation import CorrelationReport, InvestigationHypothesis
from aegis.orchestrator.actions import BrokeredDefenderActions
from aegis.orchestrator.case_runner import CaseDependencies
from aegis.policy.approval import Approval, ApprovalDecision
from aegis.providers.schemas import ProposalKind, StructuredProposal
from aegis.providers.stub import StubProvider
from aegis.range.adapter import ProxyRuleAdapter
from aegis.range.deployment import RangeDeploymentAdapter
from aegis.repair.candidate import PatchCandidate, changed_files
from aegis.verifier.models import AssuranceOutcome

CASE_ID = "AGE-0001"

GOOD_DIFF = """--- a/app.py
+++ b/app.py
@@ -10,6 +10,7 @@
 import os

 from flask import Flask, abort, request, send_file
+from werkzeug.utils import safe_join

 app = Flask(__name__)
 BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")
"""


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def scope_policy_kwargs(now: datetime) -> dict[str, Any]:
    return {
        "case_id": CASE_ID,
        "version": 1,
        "authorization": Authorization(expires_at=now + timedelta(days=7)),
        "targets": Targets(
            repositories=(RepositoryTarget(id="demo-api", commit="a" * 40),),
            services=(ServiceTarget(id="demo-api-range", network=f"range-{CASE_ID}"),),
        ),
        "network": NetworkPolicy(),
        "filesystem": FilesystemPolicy(
            read=(f"artifact://{CASE_ID}/source",),
            write=(f"workspace://{CASE_ID}/candidate",),
        ),
        "tools": ToolsPolicy(allow=("semgrep.scan", "pytest.run", "http.replay")),
        "actions": ActionsPolicy(
            auto=("evidence.read", "scan.run", "test.run", "patch.propose"),
            approval=("contain.rate_limit", "deployment.rollout"),
            deny=("host.shell", "iam.admin", "audit.modify"),
        ),
        "budgets": Budgets(
            tool_calls=100, model_tokens=100_000, wall_time_seconds=3600, spend_usd=20
        ),
    }


@pytest.fixture
def scope_policy(scope_policy_kwargs: dict[str, Any]) -> ScopePolicy:
    return ScopePolicy(**scope_policy_kwargs)


@pytest.fixture
def case(now: datetime) -> Case:
    return Case(
        id=CASE_ID,
        title="Path traversal in demo-api",
        created_at=now,
        created_by="operator:alice",
        scope_ref=f"scope://{CASE_ID}/1",
        scope_digest=Digest(digest="a" * 64),
    )


@pytest.fixture
def make_candidate(now: datetime) -> Callable[..., PatchCandidate]:
    def _make(**overrides: Any) -> PatchCandidate:
        diff = overrides.pop("diff", GOOD_DIFF)
        defaults: dict[str, Any] = {
            "id": "patch-0001",
            "case_id": CASE_ID,
            "base_repository": "path-traversal-v1",
            "base_source_digest": Digest(digest="a" * 64),
            "diff": diff,
            "diff_digest": Digest(digest=hashlib.sha256(diff.encode()).hexdigest()),
            "files_changed": changed_files(diff),
            "root_cause": "unsanitized path join allows traversal outside BASE_DIR",
            "repair_invariant": "resolved path must remain within BASE_DIR",
            "generated_at": now,
        }
        defaults.update(overrides)
        return PatchCandidate(**defaults)

    return _make


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

REFUSAL = StructuredProposal(kind=ProposalKind.REFUSE, rationale="insufficient evidence")


@pytest.fixture
def brokered_actions_factory(
    case: Case, scope_policy: ScopePolicy, now: datetime
) -> Callable[..., BrokeredDefenderActions]:
    def _make(decision: ApprovalDecision = ApprovalDecision.APPROVED) -> BrokeredDefenderActions:
        scope = scope_policy.model_copy(
            update={
                "tools": ToolsPolicy(allow=("range.proxy", "range.deployment")),
                "actions": ActionsPolicy(
                    auto=("evidence.read", "scan.run", "test.run", "patch.propose"),
                    approval=(
                        "contain.rate_limit",
                        "contain.rollback",
                        "deployment.rollout",
                        "deployment.rollback",
                    ),
                    deny=("host.shell", "iam.admin", "audit.modify"),
                ),
            }
        )
        bound_case = case.model_copy(
            update={"scope_digest": sha256_digest(scope.model_dump_json().encode())}
        )
        descriptor = AdapterDescriptor(
            id="range.proxy",
            version=1,
            category="test-containment",
            permissions=AdapterPermissions(filesystem="read-write-workspace"),
            risk_tier=RiskTier.R3_REVERSIBLE_RESPONSE,
            limits=AdapterLimits(timeout_seconds=10, cpu=1.0, memory_mb=128),
            parser="test-range-proxy-v1",
        )
        registry = AdapterRegistry()
        registry.register(
            MockAdapter(
                descriptor,
                allowed_parameter_keys=frozenset({"operation", "rollback_of"}),
                action_definitions=ProxyRuleAdapter.action_definitions,
            )
        )
        deployment_descriptor = AdapterDescriptor(
            id="range.deployment",
            version=1,
            category="test-range-deployment",
            permissions=AdapterPermissions(
                filesystem="read-write-workspace", docker_control="authorized-range"
            ),
            risk_tier=RiskTier.R4_CHANGE,
            limits=AdapterLimits(timeout_seconds=600, cpu=2.0, memory_mb=2048),
            parser="test-range-deployment-v1",
        )
        registry.register(
            MockAdapter(
                deployment_descriptor,
                allowed_parameter_keys=frozenset(
                    {
                        "operation",
                        "candidate_diff",
                        "diff_digest",
                        "base_source_digest",
                        "rollback_of",
                    }
                ),
                action_definitions=RangeDeploymentAdapter.action_definitions,
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
                decision=decision,
                decided_by="operator:alice",
                decided_at=now,
            )

        return BrokeredDefenderActions(
            coordinator=ActionTransactionCoordinator(broker),
            case=bound_case,
            scope=scope,
            approval_provider=approve,
            policy_version="unit-scope-v1",
            clock=lambda: now,
        )

    return _make


@pytest.fixture
def happy_deps(
    make_candidate: Callable[..., PatchCandidate],
    brokered_actions_factory: Callable[[ApprovalDecision], BrokeredDefenderActions],
) -> CaseDependencies:
    return CaseDependencies(
        provider=StubProvider(response=CONTAINMENT_PROPOSAL),
        brokered_actions=brokered_actions_factory(ApprovalDecision.APPROVED),
        exploit_reachable=lambda: True,
        attack_blocked=lambda: True,
        benign_available=lambda: True,
        generate_candidate=lambda: make_candidate(),
        verify_candidate=lambda _candidate: AssuranceOutcome.VERIFIED,
        deployment_target_ref="service://demo-api-range",
        recovery_attack_blocked=lambda: True,
        recovery_benign_available=lambda: True,
        investigate=lambda: CorrelationReport(
            case_id=CASE_ID,
            hypotheses=(
                InvestigationHypothesis(
                    id="hyp-unit-0001",
                    case_id=CASE_ID,
                    event_id="evt-unit-0001",
                    finding_digest=Digest(digest="b" * 64),
                    finding_tool="semgrep",
                    finding_rule_id="python.path-traversal",
                    source_file="app.py",
                    source_line=23,
                    deployment_source_digest=Digest(digest="a" * 64),
                    evidence_refs=(
                        f"artifact://{CASE_ID}/sha256/{'c' * 64}",
                        f"artifact://{CASE_ID}/sha256/{'b' * 64}",
                        f"artifact://{CASE_ID}/sha256/{'a' * 64}",
                    ),
                    summary="Synthetic unit-test hypothesis; causality is unconfirmed.",
                ),
            ),
            suspicious_events=1,
            correlated_pairs=1,
        ),
    )
