from __future__ import annotations

from datetime import UTC, datetime

from scripts.bench_patch_repair import _evaluation_record

from aegis.benchmarks.records import MetricStatus, RunOutcome


def test_http_error_attempt_record_does_not_score_model_or_missing_tokens_as_zero() -> None:
    record = _evaluation_record(
        scenario_id="path-traversal-v1",
        model="qwen38",
        source_digest="sha256:" + "a" * 64,
        started_at=datetime.now(UTC),
        duration=2.5,
        outcome=RunOutcome.INFRASTRUCTURE_ERROR,
        checks=None,
        model_generation_seconds=None,
        verifier_seconds=None,
        generation_result=None,
    )
    capability = {metric.metric_id: metric for metric in record.capability.metrics}
    efficiency = {metric.metric_id: metric for metric in record.efficiency.metrics}

    assert record.outcome is RunOutcome.INFRASTRUCTURE_ERROR
    assert capability["capability.patch_verified"].status is MetricStatus.UNAVAILABLE
    assert capability["capability.patch_verified"].value is None
    assert efficiency["efficiency.wall_clock_seconds"].value == 2.5
    assert efficiency["efficiency.tokens_total"].status is MetricStatus.UNAVAILABLE
    assert efficiency["efficiency.tokens_total"].value is None
