#!/usr/bin/env python3
"""Score fixed CDB sample predictions with an explicitly pinned upstream scorer.

The detector has no access to flags. This separate command loads flags only after
predictions exist. It imports the unmodified MIT-licensed upstream scorer; review
and pin that checkout before running. This is sample-only, not the full benchmark.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True, help="reviewed CDB checkout")
    parser.add_argument("--commit", required=True, help="exact reviewed upstream commit SHA")
    parser.add_argument("--sample-zip", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("output already exists; choose a fresh path")
    actual_commit = subprocess.run(
        ["git", "-C", str(args.upstream), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    ).stdout.strip()
    if actual_commit != args.commit:
        parser.error("upstream checkout does not match the reviewed commit")
    predictions = json.loads(args.predictions.read_text(encoding="utf-8"))
    if predictions.get("agent_mode") not in {
        "deterministic_component_baseline",
        "local_model_candidate_triage",
    }:
        parser.error("unsupported sample prediction mode")
    with zipfile.ZipFile(args.sample_zip) as bundle:
        sample_digest = hashlib.sha256(bundle.read("sample.json")).hexdigest()
        if predictions.get("sample_sha256") != sample_digest:
            parser.error("predictions were generated from a different sample payload")
        flags = json.loads(bundle.read("sample_flags.json"))
    sys.path.insert(0, str(args.upstream))
    scorer = importlib.import_module("benchmark.scorer")
    score: dict[str, Any] = scorer.score_hunt_file(args.predictions, flags)
    report = {
        "benchmark": "Cyber Defense Benchmark public sample",
        "dataset": "bundled sample only; not full benchmark",
        "upstream_commit": actual_commit,
        "sample_zip_sha256": _sha256(args.sample_zip),
        "predictions_sha256": _sha256(args.predictions),
        "detector_id": predictions["diagnostics"]["detector_id"],
        "agent_mode": predictions["agent_mode"],
        "metric_source": "unmodified benchmark.scorer.score_hunt_file",
        "score": score,
        "limitations": [
            f"One public sample, seed {predictions['seed']}; not the full multi-seed benchmark.",
            "Sample component evaluation, not a full Aegis autonomous hunt. "
            f"Prediction mode: {predictions['agent_mode']}.",
            "The upstream coverage metric does not penalize false positives; "
            "this is not precision.",
            f"The detector submitted at most {predictions['diagnostics']['submission_cap']} "
            "timestamps and used no SQL queries.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "out": str(args.out),
                "coverage_score_per_run": score["coverage_score_per_run"],
                "n_flags_detected": score["n_flags_detected"],
                "n_flags_total": score["n_flags_total"],
                "submitted_count": score["submitted_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
