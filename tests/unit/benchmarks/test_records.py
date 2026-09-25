from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.benchmarks.records import (
    AgentMode,
    BenchmarkAxis,
    BenchmarkMetric,
    BenchmarkRunRecord,
    MetricStatus,
    RunOutcome,
)


def _metric(metric_id: str = "patch.verified") -> BenchmarkMetric:
    return BenchmarkMetric(
        metric_id=metric_id,
        status=MetricStatus.MEASURED,
        value=True,
        unit="boolean",
        method="Independent verifier outcome",
        evidence_refs=("check://clean-room",),
    )


def _run() -> BenchmarkRunRecord:
    return BenchmarkRunRecord(
        run_id="run-001",
        benchmark_id="aegis.layer0.synthetic-repair",
        benchmark_version="1",
        scenario_id="path-traversal-v1",
        scenario_version="1",
        agent_mode=AgentMode.HOSTED_MODEL,
        provider="openai-compatible",
        model="qwen38",
        prompt_version="test-v1",
        repository_revision="abc123",
        working_tree_dirty=True,
        started_at="2026-09-25T12:00:00Z",
        duration_seconds=12.5,
        outcome=RunOutcome.COMPLETED,
        capability=BenchmarkAxis(metrics=(_metric(),)),
        control_safety=BenchmarkAxis(),
        efficiency=BenchmarkAxis(
            metrics=(
                BenchmarkMetric(
                    metric_id="tokens.total",
                    status=MetricStatus.UNAVAILABLE,
                    unit="tokens",
                    method="Provider usage field",
                    reason="The endpoint did not provide token usage metadata.",
                ),
            )
        ),
    )


def test_record_keeps_the_three_axes_separate_and_explicitly_unmeasured() -> None:
    record = _run()

    assert record.capability.metrics[0].value is True
    assert record.control_safety.metrics == ()
    assert record.efficiency.metrics[0].status is MetricStatus.UNAVAILABLE
    assert record.efficiency.metrics[0].value is None
    assert "composite" not in record.model_dump_json().lower()


@pytest.mark.parametrize(
    "updates",
    [
        {"value": None},
        {"value": True, "reason": "not measured"},
    ],
)
def test_metric_requires_values_to_match_measurement_status(updates: dict[str, object]) -> None:
    payload = _metric().model_dump()
    payload.update(updates)
    with pytest.raises(ValidationError):
        BenchmarkMetric.model_validate(payload)


def test_unmeasured_metrics_require_a_reason() -> None:
    with pytest.raises(ValidationError, match="require a reason"):
        BenchmarkMetric(
            metric_id="safety.scope_violations",
            status=MetricStatus.UNAVAILABLE,
            unit="count",
            method="Broker audit events",
        )


def test_duplicate_metric_ids_are_rejected_within_an_axis() -> None:
    with pytest.raises(ValidationError, match="unique"):
        BenchmarkAxis(metrics=(_metric(), _metric()))


def test_model_agent_record_requires_provider_and_model() -> None:
    payload = _run().model_dump()
    payload["provider"] = None
    with pytest.raises(ValidationError, match="require provider, model"):
        BenchmarkRunRecord.model_validate(payload)


def test_scripted_and_oracle_records_do_not_claim_model_identity() -> None:
    payload = _run().model_dump()
    payload.update(
        agent_mode=AgentMode.ORACLE,
        provider=None,
        model=None,
        prompt_version=None,
    )

    record = BenchmarkRunRecord.model_validate(payload)

    assert record.agent_mode is AgentMode.ORACLE
