"""Run bounded local repair pilots and compare ungated/gated admission.

Uses one model, identical candidates, no hidden-test feedback, no deployment.
This is a decision ablation on owned fixtures, NOT SWE-bench or quality uplift.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from aegis.benchmarks.ablation import (  # noqa: E402
    CandidateObservation,
    summarize_decision_ablation,
)
from aegis.verifier.models import CheckResult  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="qwen2.5:7b")
    parser.add_argument("--repeats", type=int, choices=range(1, 6), default=1)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.timeout < 1 or args.timeout > 600:
        parser.error("timeout must be 1..600 seconds")
    output = REPO_ROOT / "artifacts" / "benchmark_runs" / f"ollama-ablation-{uuid4().hex}"
    output.mkdir(parents=True)
    env = dict(
        os.environ, LLM_URL="http://127.0.0.1:11434", LLM_API_KEY="ollama", LLM_MODEL=args.model
    )
    observations: list[CandidateObservation] = []
    for repetition in range(args.repeats):
        for scenario in ("path-traversal-v1", "object-authorization-v1"):
            destination = output / f"{scenario}-{repetition}.json"
            print(f"Running {scenario} attempt {repetition + 1} with {args.model}", flush=True)
            with (output / f"{scenario}-{repetition}.log").open("w") as log:
                result = subprocess.run(
                    [
                        sys.executable,
                        str(REPO_ROOT / "scripts" / "bench_patch_repair.py"),
                        "--scenario",
                        scenario,
                        "--structured-output",
                        "--timeout",
                        str(args.timeout),
                        "--out",
                        str(destination),
                    ],
                    cwd=REPO_ROOT,
                    env=env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=args.timeout + 780,
                    check=False,
                )
            if not destination.is_file():
                print(f"Runner failed with exit {result.returncode}; retained log at {output}")
                return 3
            record = json.loads(destination.read_text())
            observations.append(
                CandidateObservation(
                    run_id=record["evaluation"]["run_id"],
                    scenario=scenario,
                    model=args.model,
                    candidate_present=bool(record.get("candidate_diff")),
                    infrastructure_error=record["outcome"] == "INFRASTRUCTURE_ERROR",
                    checks=tuple(
                        CheckResult.model_validate(check) for check in record.get("checks", [])
                    ),
                )
            )
    summary = summarize_decision_ablation(observations)
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    print(f"Evidence: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
