"""Versioned benchmark records with independent capability/control/efficiency axes.

These records intentionally do not compute a composite score. Unmeasured values are
represented explicitly so infrastructure failures and missing instrumentation cannot
be mistaken for either success or zero-cost execution.
"""

from __future__ import annotations

from enum import StrEnum
from math import isfinite
from typing import Annotated, Final, Literal

from pydantic import Field, StrictBool, StrictFloat, StrictInt, field_validator, model_validator

from aegis.domain.base import AegisModel, AwareDatetime, RecordId

__all__ = [
    "BENCHMARK_RUN_SCHEMA_VERSION",
    "AgentMode",
    "BenchmarkAxis",
    "BenchmarkMetric",
    "BenchmarkRunRecord",
    "MetricStatus",
    "RunOutcome",
]

BENCHMARK_RUN_SCHEMA_VERSION: Final[Literal["aegis.benchmark_run/v1"]] = "aegis.benchmark_run/v1"


class AgentMode(StrEnum):
    HOSTED_MODEL = "hosted_model"
    LOCAL_MODEL = "local_model"
    SCRIPTED = "scripted"
    ORACLE = "oracle"
    REPLAY = "replay"


class RunOutcome(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    INFRASTRUCTURE_ERROR = "infrastructure_error"
    INVALID_AGENT_OUTPUT = "invalid_agent_output"


class MetricStatus(StrEnum):
    MEASURED = "measured"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


class BenchmarkMetric(AegisModel):
    """One raw metric and its measurement provenance."""

    metric_id: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.-]*$")]
    status: MetricStatus
    value: StrictBool | StrictInt | StrictFloat | None = None
    unit: Annotated[str, Field(min_length=1, max_length=64)]
    method: Annotated[str, Field(min_length=1, max_length=500)]
    reason: Annotated[str | None, Field(min_length=1, max_length=500)] = None
    evidence_refs: tuple[Annotated[str, Field(min_length=1, max_length=2048)], ...] = ()

    @field_validator("value")
    @classmethod
    def finite_numeric_values(cls, value: bool | int | float | None) -> bool | int | float | None:
        if isinstance(value, float) and not isfinite(value):
            raise ValueError("metric values must be finite")
        return value

    @model_validator(mode="after")
    def validate_status_value(self) -> BenchmarkMetric:
        if self.status is MetricStatus.MEASURED:
            if self.value is None or self.reason is not None:
                raise ValueError("measured metrics require a value and must not have a reason")
        elif self.value is not None or not self.reason:
            raise ValueError("unmeasured metrics require a reason and must not have a value")
        return self


class BenchmarkAxis(AegisModel):
    metrics: tuple[BenchmarkMetric, ...] = ()

    @model_validator(mode="after")
    def unique_metric_ids(self) -> BenchmarkAxis:
        ids = [metric.metric_id for metric in self.metrics]
        if len(ids) != len(set(ids)):
            raise ValueError("metric IDs must be unique within an axis")
        return self


class BenchmarkRunRecord(AegisModel):
    """Reproducible run metadata and three independent metric dimensions."""

    schema_version: Literal["aegis.benchmark_run/v1"] = BENCHMARK_RUN_SCHEMA_VERSION
    run_id: RecordId
    benchmark_id: Annotated[str, Field(min_length=1, max_length=128)]
    benchmark_version: Annotated[str, Field(min_length=1, max_length=128)]
    scenario_id: Annotated[str, Field(min_length=1, max_length=128)]
    scenario_version: Annotated[str, Field(min_length=1, max_length=128)]
    agent_mode: AgentMode
    provider: Annotated[str | None, Field(max_length=128)] = None
    model: Annotated[str | None, Field(max_length=128)] = None
    prompt_version: Annotated[str | None, Field(max_length=128)] = None
    finish_reason: Annotated[str | None, Field(max_length=64)] = None
    repository_revision: Annotated[str | None, Field(max_length=128)] = None
    working_tree_dirty: bool | None = None
    dataset_digest: Annotated[str | None, Field(pattern=r"^sha256:[0-9a-f]{64}$")] = None
    started_at: AwareDatetime
    duration_seconds: Annotated[float, Field(ge=0, allow_inf_nan=False)]
    outcome: RunOutcome
    capability: BenchmarkAxis
    control_safety: BenchmarkAxis
    efficiency: BenchmarkAxis

    @model_validator(mode="after")
    def provider_model_consistency(self) -> BenchmarkRunRecord:
        if self.agent_mode in {AgentMode.HOSTED_MODEL, AgentMode.LOCAL_MODEL} and (
            not self.provider or not self.model or not self.prompt_version
        ):
            raise ValueError("model runs require provider, model, and prompt version")
        return self
