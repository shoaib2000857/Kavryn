#!/usr/bin/env python3
"""Run the local-only deterministic CDB component baseline on its public sample.

Ground-truth flags are not read here. Score the emitted JSON with the pinned
upstream ``benchmark.scorer.score_hunt_file`` in a separate step.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from aegis.benchmarks.cdb_sample import run_sample_archive  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample-zip", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-submissions", type=int, default=250)
    args = parser.parse_args()
    if args.out.exists():
        parser.error("output already exists; choose a fresh path")
    result = run_sample_archive(args.sample_zip, max_submissions=args.max_submissions)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(args.out), "diagnostics": result["diagnostics"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
