from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from aegis.domain import (
    ActionsPolicy,
    Authorization,
    Budgets,
    Digest,
    FilesystemPolicy,
    NetworkPolicy,
    RepositoryTarget,
    ScopePolicy,
    Targets,
    ToolsPolicy,
)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def sha256_digest() -> Digest:
    return Digest(digest="a" * 64)


@pytest.fixture
def scope_policy_kwargs(now: datetime) -> dict[str, Any]:
    return {
        "case_id": "AGE-0001",
        "version": 1,
        "authorization": Authorization(
            owner_attestation_required=True,
            expires_at=now + timedelta(days=7),
        ),
        "targets": Targets(repositories=(RepositoryTarget(id="demo-api", commit="a" * 40),)),
        "network": NetworkPolicy(),
        "filesystem": FilesystemPolicy(
            read=("artifact://AGE-0001/source",),
            write=("workspace://AGE-0001/candidate",),
        ),
        "tools": ToolsPolicy(allow=("semgrep.scan", "pytest.run")),
        "actions": ActionsPolicy(
            auto=("evidence.read", "scan.run"),
            approval=("deployment.rollout",),
            deny=("host.shell", "audit.modify"),
        ),
        "budgets": Budgets(
            tool_calls=100, model_tokens=100_000, wall_time_seconds=3600, spend_usd=20
        ),
    }


@pytest.fixture
def scope_policy(scope_policy_kwargs: dict[str, Any]) -> ScopePolicy:
    return ScopePolicy(**scope_policy_kwargs)
