from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from aegis.policy.approval import Approval, ApprovalDecision, resolve_approval
from aegis.workflow.states import Trigger


def _approval(now: datetime, **overrides: object) -> Approval:
    defaults: dict[str, object] = {
        "id": "approval-0001",
        "case_id": "AGE-0001",
        "subject_ref": "policy-decision://AGE-0001/dec-1",
        "requested_at": now,
        "expires_at": now + timedelta(hours=1),
    }
    defaults.update(overrides)
    return Approval(**defaults)


def test_no_approval_request_is_pending(now: datetime) -> None:
    assert resolve_approval(None, now=now) is None


def test_undecided_and_not_expired_is_pending(now: datetime) -> None:
    approval = _approval(now)
    assert resolve_approval(approval, now=now) is None


def test_undecided_and_expired_is_denied_or_expired(now: datetime) -> None:
    approval = _approval(now)
    assert resolve_approval(approval, now=now + timedelta(hours=2)) is Trigger.DENIED_OR_EXPIRED


def test_explicit_approval_resolves_to_approved(now: datetime) -> None:
    approval = _approval(
        now, decision=ApprovalDecision.APPROVED, decided_by="operator:alice", decided_at=now
    )
    assert resolve_approval(approval, now=now) is Trigger.APPROVED


def test_explicit_denial_resolves_to_denied_or_expired(now: datetime) -> None:
    approval = _approval(
        now, decision=ApprovalDecision.DENIED, decided_by="operator:alice", decided_at=now
    )
    assert resolve_approval(approval, now=now) is Trigger.DENIED_OR_EXPIRED


def test_approval_granted_before_expiry_remains_valid_when_checked_after(now: datetime) -> None:
    """Expiry bounds how long a decision may be awaited, not how long an
    already-granted decision remains valid."""
    approval = _approval(
        now, decision=ApprovalDecision.APPROVED, decided_by="operator:alice", decided_at=now
    )
    assert resolve_approval(approval, now=now + timedelta(days=1)) is Trigger.APPROVED


def test_decided_fields_required_together_with_decision(now: datetime) -> None:
    with pytest.raises(ValidationError, match="required once a decision"):
        _approval(now, decision=ApprovalDecision.APPROVED)


def test_decided_fields_forbidden_without_a_decision(now: datetime) -> None:
    with pytest.raises(ValidationError, match="must be unset"):
        _approval(now, decided_by="operator:alice")
