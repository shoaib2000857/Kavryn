"""Metadata-only VulnGym prediction validation and supplemental range-aware metrics.

This module never clones or executes benchmark repositories. Its range-aware recall
is intentionally supplemental: it is not the metric emitted by VulnGym's official
evaluator and must not be compared to official leaderboard results.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator

Line = StrictInt | StrictStr
_RANGE = re.compile(r"([1-9][0-9]*)-([1-9][0-9]*)\Z")
_LEADING_DOT_SLASH = re.compile(r"^(?:\./)+")
_MULTI_SLASH = re.compile(r"/+")


class _Location(BaseModel):
    """Relevant location fields; dataset annotation prose is intentionally ignored."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    file: Annotated[str, Field(min_length=1, max_length=2048)]
    line: Line

    @field_validator("line")
    @classmethod
    def validate_line(cls, value: int | str) -> int | str:
        if isinstance(value, bool):
            raise ValueError("line must be a positive integer or start-end range")
        if isinstance(value, int):
            if value < 1:
                raise ValueError("line must be positive")
            return value
        match = _RANGE.fullmatch(value)
        if match is None or int(match.group(1)) > int(match.group(2)):
            raise ValueError("line range must be positive start-end with start <= end")
        return value


class VulnGymEntry(BaseModel):
    """Minimal validated fields used from an official VulnGym entries.jsonl row."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    entry_id: Annotated[str, Field(min_length=1)]
    report_id: Annotated[str, Field(min_length=1)]
    repo_url: Annotated[str, Field(min_length=1)]
    commit: Annotated[str, Field(min_length=1)]
    entry_point: _Location
    critical_operation: _Location


class VulnGymPrediction(BaseModel):
    """Official-compatible prediction fields, with optional benchmark metadata."""

    model_config = ConfigDict(extra="allow", frozen=True)

    repo_url: Annotated[str, Field(min_length=1)]
    commit: Annotated[str, Field(min_length=1)]
    entry_point: _Location
    critical_operation: _Location


class VulnGymInputError(ValueError):
    """A JSONL row is malformed or does not match the benchmark contract."""


def load_jsonl_models(path: Path, model: type[BaseModel]) -> tuple[BaseModel, ...]:
    """Load and validate JSONL records without interpreting or executing row content."""
    records: list[BaseModel] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                records.append(model.model_validate_json(line))
            except (ValueError, TypeError) as exc:
                raise VulnGymInputError(f"{path}:{line_number}: invalid record: {exc}") from exc
    return tuple(records)


def normalize_path(path: str) -> str:
    """Match VulnGym's path normalization for exact, case-sensitive paths."""
    path = path.replace("\\", "/")
    path = _LEADING_DOT_SLASH.sub("", path)
    return _MULTI_SLASH.sub("/", path)


def normalize_repo(repo: str) -> str:
    """Match the official evaluator's repository-key normalization."""
    normalized = repo.strip()
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    if normalized.endswith("/"):
        normalized = normalized[:-1]
    return normalized


def _line_interval(line: int | str) -> tuple[int, int]:
    if isinstance(line, int):
        return line, line
    match = _RANGE.fullmatch(line)
    if match is None:
        raise ValueError("line is not a valid positive location or range")
    start, end = int(match.group(1)), int(match.group(2))
    if start > end:
        raise ValueError("line range start must not exceed end")
    return start, end


def _location_matches(predicted: _Location, expected: _Location, tolerance: int) -> bool:
    if normalize_path(predicted.file) != normalize_path(expected.file):
        return False
    predicted_start, predicted_end = _line_interval(predicted.line)
    expected_start, expected_end = _line_interval(expected.line)
    if predicted_end < expected_start:
        distance = expected_start - predicted_end
    elif expected_end < predicted_start:
        distance = predicted_start - expected_end
    else:
        distance = 0
    return distance <= tolerance


def _matches(prediction: VulnGymPrediction, entry: VulnGymEntry, tolerance: int) -> bool:
    return (
        normalize_repo(prediction.repo_url) == normalize_repo(entry.repo_url)
        and prediction.commit.strip().lower() == entry.commit.strip().lower()
        and _location_matches(prediction.entry_point, entry.entry_point, tolerance)
        and _location_matches(prediction.critical_operation, entry.critical_operation, tolerance)
    )


def evaluate_range_aware(
    entries: Sequence[VulnGymEntry],
    predictions: Sequence[VulnGymPrediction],
    *,
    line_tolerance: int = 5,
    dataset_release: str = "unspecified",
) -> dict[str, Any]:
    """Return supplemental recall metrics that support schema-valid line ranges.

    Unmatched predictions are counted for review, but no precision is computed because
    VulnGym's annotations/evaluator are recall-oriented and are not a complete negative
    label set for arbitrary findings.
    """
    if line_tolerance < 0:
        raise ValueError("line_tolerance must be non-negative")
    matched_entries: set[int] = set()
    matched_predictions: set[int] = set()
    by_repo_commit: dict[tuple[str, str], list[tuple[int, VulnGymEntry]]] = defaultdict(list)
    for index, entry in enumerate(entries):
        key = (normalize_repo(entry.repo_url), entry.commit.strip().lower())
        by_repo_commit[key].append((index, entry))

    for prediction_index, prediction in enumerate(predictions):
        key = (normalize_repo(prediction.repo_url), prediction.commit.strip().lower())
        for entry_index, entry in by_repo_commit.get(key, ()):
            if _matches(prediction, entry, line_tolerance):
                matched_entries.add(entry_index)
                matched_predictions.add(prediction_index)

    matched_advisories = {entries[index].report_id for index in matched_entries}
    advisory_ids = {entry.report_id for entry in entries}
    entry_total = len(entries)
    advisory_total = len(advisory_ids)
    range_entries = sum(
        isinstance(entry.entry_point.line, str) or isinstance(entry.critical_operation.line, str)
        for entry in entries
    )
    return {
        "metric_id": "vulngym_range_aware_recall_v1",
        "is_official_vulngym_metric": False,
        "dataset_release": dataset_release,
        "line_tolerance": line_tolerance,
        "matching": (
            "exact normalized path and strict endpoint role; line intervals within tolerance"
        ),
        "predictions": len(predictions),
        "predictions_matching_zero_entries": len(predictions) - len(matched_predictions),
        "entries_with_range_valued_endpoint": range_entries,
        "entry_recall": {
            "matched": len(matched_entries),
            "total": entry_total,
            "value": len(matched_entries) / entry_total if entry_total else None,
        },
        "advisory_recall": {
            "matched": len(matched_advisories),
            "total": advisory_total,
            "value": len(matched_advisories) / advisory_total if advisory_total else None,
        },
        "precision": None,
        "interpretation": (
            "Supplemental range-aware recall; not directly comparable to the official evaluator. "
            "Unmatched predictions are not asserted to be false positives."
        ),
    }


def evaluate_files(
    entries_path: Path,
    predictions_path: Path,
    *,
    line_tolerance: int = 5,
    dataset_release: str = "unspecified",
) -> dict[str, Any]:
    """Read official JSONL inputs and compute the supplemental metric."""
    raw_entries = load_jsonl_models(entries_path, VulnGymEntry)
    raw_predictions = load_jsonl_models(predictions_path, VulnGymPrediction)
    entries = [VulnGymEntry.model_validate(item) for item in raw_entries]
    predictions = [VulnGymPrediction.model_validate(item) for item in raw_predictions]
    return evaluate_range_aware(
        entries,
        predictions,
        line_tolerance=line_tolerance,
        dataset_release=dataset_release,
    )


def write_json_report(report: dict[str, Any], path: Path) -> None:
    """Write a deterministic JSON report without creating parent directories silently."""
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
