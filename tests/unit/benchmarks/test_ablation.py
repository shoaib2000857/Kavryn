from __future__ import annotations

import pytest

from aegis.benchmarks.ablation import CandidateObservation, summarize_decision_ablation
from aegis.verifier.models import CheckResult, CheckStatus


def observation(run_id: str, status: CheckStatus) -> CandidateObservation:
    return CandidateObservation(
        run_id=run_id,
        scenario="fixture",
        model="local",
        candidate_present=True,
        checks=(
            *(
                CheckResult(check_id=check_id, status=status, hard_failure=True, detail="result")
                for check_id in ("diff_policy", "public", "exploit_replay", "regression")
            ),
            CheckResult(
                check_id="source_integrity",
                status=CheckStatus.PASS,
                hard_failure=True,
                detail="trusted",
            ),
        ),
    )


def test_identical_candidates_filter_failures_without_claiming_quality_uplift() -> None:
    result = summarize_decision_ablation(
        [
            observation("good", CheckStatus.PASS),
            observation("bad", CheckStatus.FAIL),
            observation("unknown", CheckStatus.ERROR),
        ]
    )
    assert result["ungated_baseline"] == {"accepted": 3, "known_false_accepts": 1}
    assert result["aegis_gate"] == {"accepted": 1, "known_false_accepts": 0}
    assert result["inconclusive_candidates"] == 1
    assert result["model_repair_quality_uplift"] is None


def test_empty_and_unverified_candidates_do_not_become_success() -> None:
    assert summarize_decision_ablation([])["false_accept_reduction_percentage_points"] is None
    item = CandidateObservation(run_id="x", scenario="s", model="m", candidate_present=True)
    assert summarize_decision_ablation([item])["verified_candidates"] == 0


def test_duplicate_and_mixed_model_runs_rejected() -> None:
    item = observation("x", CheckStatus.PASS)
    with pytest.raises(ValueError, match="duplicate"):
        summarize_decision_ablation([item, item])
    with pytest.raises(ValueError, match="mix"):
        summarize_decision_ablation(
            [item, item.model_copy(update={"run_id": "y", "model": "other"})]
        )
