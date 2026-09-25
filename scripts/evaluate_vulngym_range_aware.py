#!/usr/bin/env python3
"""Compute Aegis's supplemental range-aware VulnGym recall (not the official metric).

This command reads only JSONL metadata and predictions. It never clones, builds, or
executes the repositories named in the benchmark.

Example:
    .venv/bin/python scripts/evaluate_vulngym_range_aware.py \
      --entries /path/to/VulnGym/data/entries.jsonl \
      --predictions predictions.jsonl \
      --dataset-release v0.1.4 \
      --json-out artifacts/benchmark_runs/vulngym-supplemental.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from aegis.benchmarks.vulngym import (  # noqa: E402
    VulnGymInputError,
    evaluate_files,
    write_json_report,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=Path, required=True, help="VulnGym entries.jsonl")
    parser.add_argument("--predictions", type=Path, required=True, help="finding JSONL")
    parser.add_argument("--dataset-release", default="unspecified")
    parser.add_argument("--line-tolerance", type=int, default=5)
    parser.add_argument("--json-out", type=Path, help="optional JSON report destination")
    args = parser.parse_args()
    try:
        report = evaluate_files(
            args.entries,
            args.predictions,
            line_tolerance=args.line_tolerance,
            dataset_release=args.dataset_release,
        )
    except (OSError, VulnGymInputError, ValueError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        write_json_report(report, args.json_out)
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
