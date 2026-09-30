"""Local, deterministic Cyber Defense Benchmark sample baseline.

This is a deliberately small component baseline, not an LLM hunter. It reads
only public event logs. The hidden flag file is never passed to this module.
The upstream benchmark's scorer must evaluate the resulting timestamps.
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "powershell_encoded",
        re.compile(r"\bpowershell(?:\.exe)?\b.{0,220}\s-(?:enc|encodedcommand)\b", re.I),
    ),
    (
        "powershell_remote",
        re.compile(r"\b(?:iex|invoke-expression|downloadstring|invoke-webrequest)\b", re.I),
    ),
    (
        "certutil_transfer",
        re.compile(r"\bcertutil(?:\.exe)?\b.{0,220}\b(?:urlcache|decode)\b", re.I),
    ),
    (
        "mshta_remote",
        re.compile(r"\bmshta(?:\.exe)?\b.{0,220}\b(?:https?://|javascript:|vbscript:)", re.I),
    ),
    ("regsvr32_scriptlet", re.compile(r"\bregsvr32(?:\.exe)?\b.{0,220}\bscrobj\.dll\b", re.I)),
    (
        "rundll32_script",
        re.compile(r"\brundll32(?:\.exe)?\b.{0,220}\b(?:javascript:|mshtml)\b", re.I),
    ),
    (
        "lsass_dump",
        re.compile(r"\b(?:procdump|comsvcs\.dll)\b.{0,220}\b(?:lsass|minidump)\b", re.I),
    ),
    ("shadow_delete", re.compile(r"\bvssadmin(?:\.exe)?\b.{0,220}\bdelete\s+shadows\b", re.I)),
    (
        "admin_add",
        re.compile(
            r"\bnet(?:\.exe)?\b.{0,220}\b(?:localgroup\s+administrators|user)\b.{0,220}\b/add\b",
            re.I,
        ),
    ),
)

_FIELDS = ("CommandLine", "ParentCommandLine", "Image", "ParentImage", "Message", "ScriptBlockText")


def _valid_timestamp(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value


def find_suspicious_timestamps(
    logs: Sequence[Mapping[str, Any]], *, max_submissions: int = 250
) -> tuple[list[str], dict[str, Any]]:
    """Apply predeclared command-pattern rules; never use benchmark flags.

    The cap and deterministic ranking are fixed before scoring. The upstream
    coverage metric does not penalize false positives, so the report includes
    how many unique timestamps were submitted for context.
    """
    if max_submissions < 1:
        raise ValueError("max_submissions must be positive")
    hits: dict[str, set[str]] = {}
    for event in logs:
        timestamp = _valid_timestamp(event.get("TimeCreated"))
        if timestamp is None:
            continue
        searchable = "\n".join(str(event.get(field, ""))[:8192] for field in _FIELDS)
        matched = {rule_id for rule_id, pattern in _RULES if pattern.search(searchable)}
        if matched:
            hits.setdefault(timestamp, set()).update(matched)
    ranked = sorted(hits, key=lambda timestamp: (-len(hits[timestamp]), timestamp))
    selected = ranked[:max_submissions]
    counts = {
        rule_id: sum(rule_id in hits[timestamp] for timestamp in selected) for rule_id, _ in _RULES
    }
    return selected, {
        "events_examined": len(logs),
        "candidate_timestamps": len(hits),
        "submitted_count": len(selected),
        "submission_cap": max_submissions,
        "matched_rule_counts": counts,
        "detector_id": "aegis_cdb_command_rules_v1",
        "interpretation": (
            "Deterministic public-log component baseline; not a model or full-agent result."
        ),
    }


def run_sample_archive(archive: Path, *, max_submissions: int = 250) -> dict[str, Any]:
    """Read only sample.json from the official archive; never open flags."""
    with zipfile.ZipFile(archive) as bundle:
        if "sample.json" not in bundle.namelist():
            raise ValueError("archive has no sample.json")
        info = bundle.getinfo("sample.json")
        if info.file_size > 500_000_000:
            raise ValueError("sample exceeds the 500 MB memory bound")
        raw = bundle.read("sample.json")
    payload = json.loads(raw)
    if not isinstance(payload, dict) or not isinstance(payload.get("logs"), list):
        raise ValueError("sample payload has no logs array")
    logs = payload["logs"]
    if any(not isinstance(event, dict) for event in logs):
        raise ValueError("sample contains a non-object event")
    predictions, diagnostics = find_suspicious_timestamps(logs, max_submissions=max_submissions)
    return {
        "benchmark": "Cyber Defense Benchmark public sample",
        "agent_mode": "deterministic_component_baseline",
        "sample_sha256": hashlib.sha256(raw).hexdigest(),
        "seed": payload.get("seed"),
        "submitted_timestamps": predictions,
        "per_turn": [{"turn": 1, "n_new_submitted": len(predictions), "queries_used": 0}],
        "turns": 1,
        "outcome": "terminated",
        "diagnostics": diagnostics,
    }
