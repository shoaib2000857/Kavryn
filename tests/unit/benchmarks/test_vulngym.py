from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis.benchmarks.vulngym import (
    VulnGymEntry,
    VulnGymPrediction,
    evaluate_files,
    evaluate_range_aware,
)


def _entry(
    *,
    entry_id: str = "entry-00001",
    report_id: str = "GHSA-AAAA-BBBB-CCCC",
    entry_line: int | str = 10,
    operation_line: int | str = "20-23",
    repo_url: str = "https://github.com/example/project",
    commit: str = "a" * 40,
) -> VulnGymEntry:
    return VulnGymEntry.model_validate(
        {
            "entry_id": entry_id,
            "report_id": report_id,
            "repo_url": repo_url,
            "commit": commit,
            "entry_point": {"file": "./src\\handler.py", "line": entry_line},
            "critical_operation": {"file": "src/sink.py", "line": operation_line},
            "desc": "ignored untrusted annotation prose",
        }
    )


def _prediction(
    *,
    entry_line: int | str = 10,
    operation_line: int | str = 22,
    repo_url: str = "https://github.com/example/project.git",
    commit: str = "A" * 40,
    entry_file: str = "src/handler.py",
    operation_file: str = "src/sink.py",
) -> VulnGymPrediction:
    return VulnGymPrediction.model_validate(
        {
            "repo_url": repo_url,
            "commit": commit,
            "entry_point": {"file": entry_file, "line": entry_line},
            "critical_operation": {"file": operation_file, "line": operation_line},
            "finding_id": "optional-extra-field",
        }
    )


def test_range_aware_metric_matches_exact_range_annotation() -> None:
    report = evaluate_range_aware([_entry()], [_prediction()], dataset_release="v0.1.4")

    assert report["is_official_vulngym_metric"] is False
    assert report["dataset_release"] == "v0.1.4"
    assert report["entries_with_range_valued_endpoint"] == 1
    assert report["entry_recall"] == {"matched": 1, "total": 1, "value": 1.0}
    assert report["advisory_recall"] == {"matched": 1, "total": 1, "value": 1.0}
    assert report["precision"] is None


def test_matching_is_strict_about_endpoint_roles_repo_and_commit() -> None:
    entry = _entry()
    wrong_role = _prediction(entry_line=22, operation_line=10)
    wrong_repo = _prediction(repo_url="https://github.com/other/project")
    wrong_commit = _prediction(commit="b" * 40)

    report = evaluate_range_aware([entry], [wrong_role, wrong_repo, wrong_commit])

    assert report["entry_recall"]["matched"] == 0
    assert report["predictions_matching_zero_entries"] == 3


def test_tolerance_uses_interval_distance_and_does_not_inflate_duplicates() -> None:
    entry = _entry()
    within = _prediction(operation_line=28)
    outside = _prediction(operation_line=29)
    duplicate = _prediction(operation_line=22)

    report = evaluate_range_aware([entry], [within, outside, duplicate], line_tolerance=5)

    assert report["entry_recall"]["matched"] == 1
    assert report["predictions_matching_zero_entries"] == 1


@pytest.mark.parametrize("line", [0, -1, "0-3", "5-4", "3-", "x-y", True])
def test_invalid_line_locations_are_rejected(line: object) -> None:
    with pytest.raises(ValidationError):
        _entry(operation_line=line)  # type: ignore[arg-type]


def test_line_tolerance_must_be_non_negative() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        evaluate_range_aware([_entry()], [], line_tolerance=-1)


def test_jsonl_file_evaluator_handles_realistic_range_schema(tmp_path: Path) -> None:
    entries_path = tmp_path / "entries.jsonl"
    predictions_path = tmp_path / "predictions.jsonl"
    entries_path.write_text(_entry().model_dump_json() + "\n", encoding="utf-8")
    predictions_path.write_text(_prediction().model_dump_json() + "\n", encoding="utf-8")

    report = evaluate_files(entries_path, predictions_path, dataset_release="test")

    assert report["entry_recall"]["value"] == 1.0
    assert report["advisory_recall"]["value"] == 1.0


def test_empty_ground_truth_returns_null_recall() -> None:
    report = evaluate_range_aware([], [_prediction()])

    assert report["entry_recall"]["value"] is None
    assert report["advisory_recall"]["value"] is None
