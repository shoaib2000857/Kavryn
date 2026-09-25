from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

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
from aegis.orchestrator.case_runner import CaseDependencies
from aegis.providers.schemas import ProposalKind, StructuredProposal
from aegis.providers.stub import StubProvider
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
            "diff_digest": Digest(digest="b" * 64),
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
def happy_deps(make_candidate: Callable[..., PatchCandidate]) -> CaseDependencies:
    return CaseDependencies(
        provider=StubProvider(response=CONTAINMENT_PROPOSAL),
        exploit_reachable=lambda: True,
        approve_containment=lambda: True,
        apply_containment=lambda: None,
        rollback_containment=lambda: None,
        attack_blocked=lambda: True,
        benign_available=lambda: True,
        generate_candidate=lambda: make_candidate(),
        verify_candidate=lambda _candidate: AssuranceOutcome.VERIFIED,
        approve_deployment=lambda: True,
        recovery_attack_blocked=lambda: True,
        recovery_benign_available=lambda: True,
    )
