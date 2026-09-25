from __future__ import annotations

from aegis.verifier.gate import evaluate_assurance
from aegis.verifier.models import AssuranceOutcome, CheckResult, CheckStatus


def _check(check_id: str, status: CheckStatus, hard_failure: bool = True) -> CheckResult:
    return CheckResult(check_id=check_id, status=status, hard_failure=hard_failure, detail="x")


def test_no_checks_is_review_required() -> None:
    assert evaluate_assurance(()) is AssuranceOutcome.REVIEW_REQUIRED


def test_all_checks_passing_is_verified() -> None:
    checks = (_check("a", CheckStatus.PASS), _check("b", CheckStatus.PASS))
    assert evaluate_assurance(checks) is AssuranceOutcome.VERIFIED


def test_a_hard_failure_is_rejected() -> None:
    checks = (_check("a", CheckStatus.PASS), _check("exploit_replay", CheckStatus.FAIL))
    assert evaluate_assurance(checks) is AssuranceOutcome.REJECTED


def test_source_integrity_hard_failure_is_control_failure_not_rejected() -> None:
    checks = (_check("a", CheckStatus.PASS), _check("source_integrity", CheckStatus.FAIL))
    assert evaluate_assurance(checks) is AssuranceOutcome.CONTROL_FAILURE


def test_control_failure_takes_priority_over_an_ordinary_hard_failure() -> None:
    checks = (
        _check("exploit_replay", CheckStatus.FAIL),
        _check("source_integrity", CheckStatus.FAIL),
    )
    assert evaluate_assurance(checks) is AssuranceOutcome.CONTROL_FAILURE


def test_an_error_with_no_hard_failure_is_review_required() -> None:
    checks = (_check("a", CheckStatus.PASS), _check("clean_room_tests", CheckStatus.ERROR))
    assert evaluate_assurance(checks) is AssuranceOutcome.REVIEW_REQUIRED


def test_a_hard_failure_takes_priority_over_an_error() -> None:
    checks = (
        _check("exploit_replay", CheckStatus.FAIL),
        _check("clean_room_tests", CheckStatus.ERROR),
    )
    assert evaluate_assurance(checks) is AssuranceOutcome.REJECTED


def test_a_soft_failure_alone_is_review_required_not_verified() -> None:
    checks = (
        _check("a", CheckStatus.PASS),
        _check("security_rescan", CheckStatus.FAIL, hard_failure=False),
    )
    assert evaluate_assurance(checks) is AssuranceOutcome.REVIEW_REQUIRED


def test_soft_failure_does_not_mask_a_hard_failure() -> None:
    checks = (
        _check("security_rescan", CheckStatus.FAIL, hard_failure=False),
        _check("exploit_replay", CheckStatus.FAIL, hard_failure=True),
    )
    assert evaluate_assurance(checks) is AssuranceOutcome.REJECTED
