"""Paired decision ablation on identical candidates, not model-quality uplift.

The ungated baseline accepts every parsed, in-scope candidate. Both arms use
the same independent outcome labels. Neither arm deploys anything here.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import Field

from aegis.domain.base import AegisModel
from aegis.verifier.gate import evaluate_assurance
from aegis.verifier.models import AssuranceOutcome, CheckResult


class CandidateObservation(AegisModel):
    run_id: str = Field(min_length=1)
    scenario: str = Field(min_length=1)
    model: str = Field(min_length=1)
    candidate_present: bool
    infrastructure_error: bool = False
    checks: tuple[CheckResult, ...] = ()


def summarize_decision_ablation(observations: Sequence[CandidateObservation]) -> dict[str, object]:
    """Retain all attempts; count infrastructure failures separately from rejects."""
    ids = [item.run_id for item in observations]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate run IDs would inflate the comparison")
    if len({item.model for item in observations}) > 1:
        raise ValueError("same-model ablation cannot mix model identifiers")
    candidates = [item for item in observations if item.candidate_present]
    required_checks = {"source_integrity", "diff_policy", "public", "exploit_replay", "regression"}
    verified = sum(
        required_checks.issubset({check.check_id for check in item.checks})
        and evaluate_assurance(item.checks) is AssuranceOutcome.VERIFIED
        for item in candidates
    )
    known_failures = sum(
        evaluate_assurance(item.checks) is AssuranceOutcome.REJECTED for item in candidates
    )
    inconclusive = len(candidates) - verified - known_failures
    return {
        "comparison_version": "aegis.decision-ablation/v1",
        "method": "identical-candidate counterfactual admission; no actual deployment",
        "standard_benchmark": False,
        "attempts": len(observations),
        "infrastructure_errors": sum(item.infrastructure_error for item in observations),
        "parsed_candidates": len(candidates),
        "verified_candidates": verified,
        "known_failed_candidates": known_failures,
        "inconclusive_candidates": inconclusive,
        "ungated_baseline": {"accepted": len(candidates), "known_false_accepts": known_failures},
        "aegis_gate": {"accepted": verified, "known_false_accepts": 0},
        "false_accept_reduction_percentage_points": (
            100.0 * known_failures / len(candidates) if candidates else None
        ),
        "model_repair_quality_uplift": None,
        "limitation": "Admission filtering changes acceptance, not generated patch quality. "
        "This is not a comparison to a test-aware CLI or an iterative agent; fixtures are small "
        "and verifier failures may reveal infrastructure errors requiring investigation.",
        "run_ids": ids,
    }
