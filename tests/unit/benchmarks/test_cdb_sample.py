from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from aegis.benchmarks.cdb_sample import find_suspicious_timestamps, run_sample_archive


def test_rules_select_suspicious_event_without_flags() -> None:
    logs = [
        {"TimeCreated": "2026-01-01T00:00:00Z", "CommandLine": "notepad.exe"},
        {
            "TimeCreated": "2026-01-01T00:00:01Z",
            "CommandLine": "powershell.exe -EncodedCommand AAAA",
        },
    ]
    timestamps, diagnostics = find_suspicious_timestamps(logs)
    assert timestamps == ["2026-01-01T00:00:01Z"]
    assert diagnostics["events_examined"] == 2
    assert diagnostics["matched_rule_counts"]["powershell_encoded"] == 1


def test_submission_cap_and_invalid_timestamp() -> None:
    logs = [
        {"TimeCreated": "not-a-time", "CommandLine": "powershell.exe -enc AAAA"},
        {"TimeCreated": "2026-01-01T00:00:02Z", "CommandLine": "powershell.exe -enc BBBB"},
        {"TimeCreated": "2026-01-01T00:00:01Z", "CommandLine": "powershell.exe -enc CCCC"},
    ]
    timestamps, diagnostics = find_suspicious_timestamps(logs, max_submissions=1)
    assert timestamps == ["2026-01-01T00:00:01Z"]
    assert diagnostics["candidate_timestamps"] == 2
    with pytest.raises(ValueError, match="positive"):
        find_suspicious_timestamps(logs, max_submissions=0)


def test_archive_reader_ignores_flags(tmp_path: Path) -> None:
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(
            "sample.json",
            json.dumps(
                {
                    "seed": 1,
                    "logs": [
                        {
                            "TimeCreated": "2026-01-01T00:00:01Z",
                            "CommandLine": "certutil -urlcache https://example.invalid",
                        }
                    ],
                }
            ),
        )
        bundle.writestr("sample_flags.json", "this is deliberately invalid JSON")
    result = run_sample_archive(archive)
    assert result["seed"] == 1
    assert result["submitted_timestamps"] == ["2026-01-01T00:00:01Z"]
    assert result["agent_mode"] == "deterministic_component_baseline"
