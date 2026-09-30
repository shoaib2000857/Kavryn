"""The assurance gate: a pure, deterministic decision function.

See docs/EVIDENCE_AND_ASSURANCE.md "Hard failures":
non-compensating — no combination of passing checks or model confidence
can outweigh one. This function is the only place that rule is applied,
and it never inspects anything but the ``CheckResult`` tuple it is
given (no I/O, no model access).
"""

from __future__ import annotations

from aegis.verifier.models import AssuranceOutcome, CheckResult, CheckStatus

__all__ = ["evaluate_assurance"]

# Checks whose hard failure means the evaluation *process* itself cannot
# be trusted (a tampered or mismatched base source), as distinct from
# "the patch itself is bad" -- these route to CONTROL_FAILURE, not
# REJECTED (docs/WORKFLOWS.md: "Evidence integrity failure ->
# CONTROL_FAILURE and case stop").
_INTEGRITY_CHECK_IDS = frozenset({"source_integrity", "diff_integrity"})


def evaluate_assurance(checks: tuple[CheckResult, ...]) -> AssuranceOutcome:
    if not checks:
        return AssuranceOutcome.REVIEW_REQUIRED

    for check in checks:
        if (
            check.status is CheckStatus.FAIL
            and check.hard_failure
            and check.check_id in _INTEGRITY_CHECK_IDS
        ):
            return AssuranceOutcome.CONTROL_FAILURE

    for check in checks:
        if check.status is CheckStatus.FAIL and check.hard_failure:
            return AssuranceOutcome.REJECTED

    for check in checks:
        if check.status is CheckStatus.ERROR:
            return AssuranceOutcome.REVIEW_REQUIRED

    for check in checks:
        if check.status is CheckStatus.FAIL and not check.hard_failure:
            return AssuranceOutcome.REVIEW_REQUIRED

    return AssuranceOutcome.VERIFIED
