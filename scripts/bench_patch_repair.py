"""Run one synthetic model-generated repair through Aegis's clean-room verifier.

This is a Layer-0 fixture pilot, not SWE-bench/Vul4J or a general model score.
It sends only one selected owned fixture's app.py and vulnerability summary to
the configured provider; hidden tests stay mounted only in the network-disabled
verifier container.

Usage (with the project's ignored local environment file):

    set -a; source .env.local; set +a
    .venv/bin/python scripts/bench_patch_repair.py --scenario path-traversal-v1
    .venv/bin/python scripts/bench_patch_repair.py --scenario object-authorization-v1
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from aegis.benchmarks.records import (  # noqa: E402
    AgentMode,
    BenchmarkAxis,
    BenchmarkMetric,
    BenchmarkRunRecord,
    MetricStatus,
    RunOutcome,
)
from aegis.providers.hosted import HostedApiError, HostedProviderConfig  # noqa: E402
from aegis.repair.hashing import hash_source_tree  # noqa: E402
from aegis.repair.provider import (  # noqa: E402
    HostedPatchProvider,
    PatchGenerationError,
    PatchGenerationRequest,
    PatchGenerationResult,
)
from aegis.verifier.checks import (  # noqa: E402
    check_clean_room_tests,
    check_diff_policy,
    check_source_integrity,
)
from aegis.verifier.gate import evaluate_assurance  # noqa: E402
from aegis.verifier.models import CheckResult, CheckStatus  # noqa: E402


@dataclass(frozen=True)
class RepairScenario:
    case_id: str
    fixture_name: str
    vulnerability_summary: str

    @property
    def fixture(self) -> Path:
        return REPO_ROOT / "ranges" / self.fixture_name

    @property
    def source_dir(self) -> Path:
        return self.fixture / "src"


SCENARIOS = {
    "path-traversal-v1": RepairScenario(
        case_id="AGE-PATCH-PILOT-01",
        fixture_name="path-traversal-v1",
        vulnerability_summary=(
            "The download route joins a user-controlled filename to BASE_DIR without "
            "constraining the resolved path; traversal can read a sibling secret fixture. "
            "Preserve ordinary in-root downloads."
        ),
    ),
    "object-authorization-v1": RepairScenario(
        case_id="AGE-OBJECT-AUTH-PILOT-01",
        fixture_name="object-authorization-v1",
        vulnerability_summary=(
            "The document endpoint authenticates a synthetic principal but returns any "
            "existing document without comparing the document owner with that principal. "
            "Deny cross-owner access while preserving owner access and invalid-token behavior."
        ),
    ),
}
ALLOWED_FILES = frozenset({"app.py"})
BENCHMARK_ID = "aegis.layer0.synthetic-repair"
PATCH_PROMPT_VERSION = "full-source-v2"


def _measured(
    metric_id: str,
    value: bool | int | float,
    unit: str,
    method: str,
    *,
    evidence_refs: tuple[str, ...] = (),
) -> BenchmarkMetric:
    return BenchmarkMetric(
        metric_id=metric_id,
        status=MetricStatus.MEASURED,
        value=value,
        unit=unit,
        method=method,
        evidence_refs=evidence_refs,
    )


def _unavailable(metric_id: str, unit: str, method: str, reason: str) -> BenchmarkMetric:
    return BenchmarkMetric(
        metric_id=metric_id,
        status=MetricStatus.UNAVAILABLE,
        unit=unit,
        method=method,
        reason=reason,
    )


def _check_metric(checks: tuple[CheckResult, ...] | None, check_id: str) -> BenchmarkMetric:
    method = "Independent clean-room verifier CheckResult"
    if checks is None:
        return _unavailable(
            f"control.{check_id}", "boolean", method, "Verifier did not run for this attempt."
        )
    result = next((check for check in checks if check.check_id == check_id), None)
    if result is None:
        return _unavailable(
            f"control.{check_id}", "boolean", method, "Verifier emitted no result for this check."
        )
    return _measured(
        f"control.{check_id}",
        result.status is CheckStatus.PASS,
        "boolean",
        method,
        evidence_refs=(f"check://{check_id}",),
    )


def _repository_state() -> tuple[str | None, bool | None]:
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        dirty = (
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
            != ""
        )
        return revision, dirty
    except (OSError, subprocess.SubprocessError):
        return None, None


def _evaluation_record(
    *,
    scenario_id: str,
    model: str,
    source_digest: str,
    started_at: datetime,
    duration: float,
    outcome: RunOutcome,
    checks: tuple[CheckResult, ...] | None,
    model_generation_seconds: float | None,
    verifier_seconds: float | None,
    generation_result: PatchGenerationResult | None,
) -> BenchmarkRunRecord:
    revision, dirty = _repository_state()
    check_results = checks or ()
    completed = checks is not None
    passed = sum(check.status is CheckStatus.PASS for check in check_results)
    capability_metrics = [
        (
            _measured(
                "capability.patch_verified",
                outcome is RunOutcome.COMPLETED
                and evaluate_assurance(check_results).value == "verified",
                "boolean",
                "Independent assurance gate over clean-room check results",
                evidence_refs=tuple(f"check://{check.check_id}" for check in check_results),
            )
            if completed
            else _unavailable(
                "capability.patch_verified",
                "boolean",
                "Independent assurance gate over clean-room check results",
                "No patch candidate reached the verifier.",
            )
        ),
        (
            _measured(
                "capability.checks_passed",
                passed,
                "checks",
                "Count of passing independent verifier checks",
            )
            if completed
            else _unavailable(
                "capability.checks_passed",
                "checks",
                "Count of passing independent verifier checks",
                "No patch candidate reached the verifier.",
            )
        ),
        (
            _measured(
                "capability.checks_total",
                len(check_results),
                "checks",
                "Count of checks emitted by the independent verifier",
            )
            if completed
            else _unavailable(
                "capability.checks_total",
                "checks",
                "Count of checks emitted by the independent verifier",
                "No patch candidate reached the verifier.",
            )
        ),
    ]
    control_metrics = [
        _check_metric(checks, check_id)
        for check_id in ("source_integrity", "diff_policy", "exploit_replay", "regression")
    ]
    control_metrics.extend(
        (
            _measured(
                "control.verifier_network_disabled",
                True,
                "boolean",
                "The repair pilot constructs clean-room verifier requests with network=none",
            ),
            _measured(
                "control.hidden_tests_not_in_model_context",
                True,
                "boolean",
                "The model request contains only app.py and a vulnerability summary; "
                "hidden tests are mounted only in the verifier",
            ),
        )
    )
    efficiency_metrics = [
        _measured(
            "efficiency.wall_clock_seconds",
            round(duration, 3),
            "seconds",
            "Monotonic process timer",
        ),
        _measured(
            "efficiency.provider_requests",
            1,
            "requests",
            "One hosted patch-generation request was attempted",
        ),
        (
            _measured(
                "efficiency.model_generation_seconds",
                round(model_generation_seconds, 3),
                "seconds",
                "Monotonic timer around provider generation",
            )
            if model_generation_seconds is not None
            else _unavailable(
                "efficiency.model_generation_seconds",
                "seconds",
                "Monotonic timer around provider generation",
                "Provider did not return a valid patch candidate.",
            )
        ),
        (
            _measured(
                "efficiency.verifier_seconds",
                round(verifier_seconds, 3),
                "seconds",
                "Monotonic timer around image preparation and clean-room verification",
            )
            if verifier_seconds is not None
            else _unavailable(
                "efficiency.verifier_seconds",
                "seconds",
                "Monotonic timer around image preparation and clean-room verification",
                "Verifier did not run.",
            )
        ),
        *[
            (
                _measured(
                    f"efficiency.tokens_{name}",
                    value,
                    "tokens",
                    f"OpenAI-compatible usage.{name} from the provider response",
                )
                if value is not None
                else _unavailable(
                    f"efficiency.tokens_{name}",
                    "tokens",
                    f"OpenAI-compatible usage.{name} from the provider response",
                    "Provider response omitted this token count.",
                )
            )
            for name, value in (
                (
                    "prompt",
                    generation_result.usage.prompt_tokens
                    if generation_result and generation_result.usage
                    else None,
                ),
                (
                    "completion",
                    generation_result.usage.completion_tokens
                    if generation_result and generation_result.usage
                    else None,
                ),
                (
                    "total",
                    generation_result.usage.total_tokens
                    if generation_result and generation_result.usage
                    else None,
                ),
            )
        ],
    ]
    return BenchmarkRunRecord(
        run_id=f"run-{uuid4().hex}",
        benchmark_id=BENCHMARK_ID,
        benchmark_version="1",
        scenario_id=scenario_id,
        scenario_version="1",
        agent_mode=AgentMode.HOSTED_MODEL,
        provider="openai-compatible-hosted",
        model=model,
        prompt_version=PATCH_PROMPT_VERSION,
        finish_reason=generation_result.finish_reason if generation_result else None,
        repository_revision=revision,
        working_tree_dirty=dirty,
        dataset_digest=source_digest,
        started_at=started_at,
        duration_seconds=round(duration, 3),
        outcome=outcome,
        capability=BenchmarkAxis(metrics=tuple(capability_metrics)),
        control_safety=BenchmarkAxis(metrics=tuple(control_metrics)),
        efficiency=BenchmarkAxis(metrics=tuple(efficiency_metrics)),
    )


def _build_verifier() -> str:
    dockerfile = REPO_ROOT / "docker" / "verifier" / "Dockerfile"
    tag = "aegis-verifier:repair-pilot"
    subprocess.run(
        ["docker", "build", "-t", tag, "-f", str(dockerfile), str(dockerfile.parent)],
        check=True,
        timeout=600,
    )
    result = subprocess.run(
        ["docker", "inspect", tag, "--format={{.Id}}"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


def main() -> int:
    wall_started = time.perf_counter()
    started_at = datetime.now(UTC)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="write the machine-readable result bundle")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument(
        "--scenario",
        choices=tuple(SCENARIOS),
        default="path-traversal-v1",
        help="owned synthetic fixture to repair; does not select a standard benchmark",
    )
    args = parser.parse_args()
    scenario = SCENARIOS[args.scenario]
    if not (scenario.source_dir / "app.py").is_file():
        parser.error(f"fixture source does not exist: {scenario.source_dir / 'app.py'}")

    endpoint = os.environ.get("LLM_URL", "").strip()
    api_key = os.environ.get("LLM_API_KEY", "")
    model = os.environ.get("LLM_MODEL", "qwen38")
    if not endpoint or not api_key:
        parser.error("hosted pilot requires LLM_URL and LLM_API_KEY in the environment")
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        parser.error("refusing to send the API key to a non-local HTTP endpoint")
    base_url = endpoint.rstrip("/")
    if not base_url.endswith("/v1"):
        base_url += "/v1"

    config = HostedProviderConfig(
        base_url=base_url,
        model=model,
        timeout_seconds=float(args.timeout),
        reasoning_effort="none",
    )
    source_text = (scenario.source_dir / "app.py").read_text(encoding="utf-8")
    source_digest = hash_source_tree(str(scenario.source_dir))
    request = PatchGenerationRequest(
        case_id=scenario.case_id,
        base_repository=scenario.fixture_name,
        base_source_digest=source_digest,
        source_file="app.py",
        source=source_text,
        vulnerability_summary=scenario.vulnerability_summary,
        allowed_files=ALLOWED_FILES,
    )

    started = time.perf_counter()
    try:
        generation_result = HostedPatchProvider(config, api_key=api_key).generate_with_metadata(
            request
        )
        candidate = generation_result.candidate
    except HostedApiError as exc:
        result = {
            "benchmark": "Aegis Layer-0 synthetic repair pilot",
            "benchmark_layer": 0,
            "not_a_standard_benchmark": True,
            "scenario": args.scenario,
            "case_id": request.case_id,
            "provider": "openai-compatible-hosted",
            "model": model,
            "outcome": "INFRASTRUCTURE_ERROR",
            "error": str(exc),
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "evaluation": _evaluation_record(
                scenario_id=args.scenario,
                model=model,
                source_digest=f"sha256:{source_digest.digest}",
                started_at=started_at,
                duration=time.perf_counter() - wall_started,
                outcome=RunOutcome.INFRASTRUCTURE_ERROR,
                checks=None,
                model_generation_seconds=None,
                verifier_seconds=None,
                generation_result=None,
            ).model_dump(mode="json"),
        }
        _emit_result(result, args.out)
        return 3
    except PatchGenerationError as exc:
        result = {
            "benchmark": "Aegis Layer-0 synthetic repair pilot",
            "benchmark_layer": 0,
            "not_a_standard_benchmark": True,
            "scenario": args.scenario,
            "case_id": request.case_id,
            "provider": "openai-compatible-hosted",
            "model": model,
            "outcome": "INVALID_MODEL_OUTPUT",
            "error": str(exc),
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "evaluation": _evaluation_record(
                scenario_id=args.scenario,
                model=model,
                source_digest=f"sha256:{source_digest.digest}",
                started_at=started_at,
                duration=time.perf_counter() - wall_started,
                outcome=RunOutcome.INVALID_AGENT_OUTPUT,
                checks=None,
                model_generation_seconds=None,
                verifier_seconds=None,
                generation_result=None,
            ).model_dump(mode="json"),
        }
        _emit_result(result, args.out)
        return 4
    model_elapsed = time.perf_counter() - started
    verifier_started = time.perf_counter()
    verifier_image = _build_verifier()

    with tempfile.TemporaryDirectory(prefix="aegis-patch-pilot-") as temp_dir:
        diff_file = Path(temp_dir) / "candidate.diff"
        diff_file.write_text(candidate.diff)
        checks = (
            check_source_integrity(candidate, trusted_source_dir=str(scenario.source_dir)),
            check_diff_policy(candidate, allowed_files=ALLOWED_FILES),
            *check_clean_room_tests(
                image_ref=verifier_image,
                trusted_source_dir=str(scenario.source_dir),
                diff_file=str(diff_file),
                public_tests_dir=str(scenario.fixture / "public_tests"),
                hidden_tests_dir=str(scenario.fixture / "hidden_tests"),
            ),
        )
    outcome = evaluate_assurance(checks)
    verifier_elapsed = time.perf_counter() - verifier_started
    run_outcome = RunOutcome.COMPLETED if outcome.value == "verified" else RunOutcome.FAILED
    success_result: dict[str, object] = {
        "benchmark": "Aegis Layer-0 synthetic repair pilot",
        "benchmark_layer": 0,
        "not_a_standard_benchmark": True,
        "scenario": args.scenario,
        "case_id": request.case_id,
        "provider": "openai-compatible-hosted",
        "model": model,
        "model_generation_seconds": round(model_elapsed, 3),
        "source_digest": source_digest.model_dump(mode="json"),
        "verifier_image": verifier_image,
        "candidate_id": candidate.id,
        "candidate_diff_digest": candidate.diff_digest.digest,
        "files_changed": candidate.files_changed,
        "root_cause": candidate.root_cause,
        "repair_invariant": candidate.repair_invariant,
        "outcome": outcome.value,
        "checks": [check.model_dump(mode="json") for check in checks],
        "candidate_diff": candidate.diff,
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "evaluation": _evaluation_record(
            scenario_id=args.scenario,
            model=model,
            source_digest=f"sha256:{source_digest.digest}",
            started_at=started_at,
            duration=time.perf_counter() - wall_started,
            outcome=run_outcome,
            checks=checks,
            model_generation_seconds=model_elapsed,
            verifier_seconds=verifier_elapsed,
            generation_result=generation_result,
        ).model_dump(mode="json"),
    }
    _emit_result(success_result, args.out)
    return 0 if outcome.value == "verified" else 2


def _emit_result(result: dict[str, object], output: Path | None) -> None:
    rendered = json.dumps(result, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n")
    print(rendered)


if __name__ == "__main__":
    raise SystemExit(main())
