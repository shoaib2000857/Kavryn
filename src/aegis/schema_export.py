"""Generate versioned JSON Schema documents for every registered domain model.

Used by ``scripts/export_schemas.py`` (the developer/CI entrypoint) and by
``tests/unit/domain/test_schema_export.py`` (drift detection).
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from aegis.benchmarks.records import BENCHMARK_RUN_SCHEMA_VERSION, BenchmarkRunRecord
from aegis.core.actions import ActionDefinition
from aegis.core.capability import Capability
from aegis.core.coordinator import VerificationOutcome
from aegis.core.receipt import ExecutionReceipt
from aegis.core.sandbox import (
    SANDBOX_REQUEST_SCHEMA_VERSION,
    SANDBOX_RESULT_SCHEMA_VERSION,
    SandboxExecutionRequest,
    SandboxExecutionResult,
)
from aegis.core.transaction import ActionTransaction
from aegis.domain.registry import SCHEMA_REGISTRY
from aegis.investigation.correlation import (
    CorrelationReport,
    InvestigationHypothesis,
    RouteSourceBinding,
)
from aegis.monitoring.behavioral import BehavioralAssessment
from aegis.policy.approval import Approval

SCHEMAS_DIR = Path(__file__).resolve().parent.parent.parent / "schemas"

__all__ = ["SCHEMAS_DIR", "generate"]


def _filename(schema_version: str) -> str:
    return schema_version.replace("/", ".") + ".json"


def generate() -> dict[str, str]:
    """Return {filename: rendered JSON schema text} for every registered model."""
    rendered: dict[str, str] = {}
    schema_registry: dict[str, type[BaseModel]] = {
        **SCHEMA_REGISTRY,
        "aegis.action_definition/v1": ActionDefinition,
        "aegis.action_transaction/v1": ActionTransaction,
        "aegis.approval/v1": Approval,
        "aegis.capability/v1": Capability,
        "aegis.verification_outcome/v1": VerificationOutcome,
        "aegis.execution_receipt/v1": ExecutionReceipt,
        SANDBOX_REQUEST_SCHEMA_VERSION: SandboxExecutionRequest,
        SANDBOX_RESULT_SCHEMA_VERSION: SandboxExecutionResult,
        "aegis.behavioral_assessment/v1": BehavioralAssessment,
        "aegis.correlation_report/v1": CorrelationReport,
        "aegis.investigation_hypothesis/v1": InvestigationHypothesis,
        "aegis.route_source_binding/v1": RouteSourceBinding,
        BENCHMARK_RUN_SCHEMA_VERSION: BenchmarkRunRecord,
    }
    for schema_version, model in sorted(schema_registry.items()):
        schema = model.model_json_schema()
        text = json.dumps(schema, indent=2, sort_keys=True) + "\n"
        rendered[_filename(schema_version)] = text
    return rendered
