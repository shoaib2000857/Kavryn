from __future__ import annotations

import json

import pytest

from aegis.tools.findings import FindingsParseError, parse_bandit_json, parse_semgrep_json

VALID_SEMGREP = json.dumps(
    {
        "results": [
            {
                "check_id": "python.lang.security.audit.path-traversal",
                "path": "app.py",
                "start": {"line": 17},
                "extra": {"severity": "ERROR", "message": "possible path traversal"},
            }
        ]
    }
)

VALID_BANDIT = json.dumps(
    {
        "results": [
            {
                "test_id": "B108",
                "filename": "app.py",
                "line_number": 17,
                "issue_severity": "HIGH",
                "issue_text": "Probable insecure usage of temp file/directory.",
            }
        ]
    }
)


def test_parses_valid_semgrep_output() -> None:
    findings = parse_semgrep_json(VALID_SEMGREP)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == "semgrep"
    assert finding.rule_id == "python.lang.security.audit.path-traversal"
    assert finding.file == "app.py"
    assert finding.line == 17
    assert finding.severity == "ERROR"


def test_parses_valid_bandit_output() -> None:
    findings = parse_bandit_json(VALID_BANDIT)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == "bandit"
    assert finding.rule_id == "B108"
    assert finding.severity == "HIGH"


def test_empty_results_list_is_not_an_error() -> None:
    assert parse_semgrep_json(json.dumps({"results": []})) == ()
    assert parse_bandit_json(json.dumps({"results": []})) == ()


def test_non_json_output_raises() -> None:
    with pytest.raises(FindingsParseError):
        parse_semgrep_json("not json at all")
    with pytest.raises(FindingsParseError):
        parse_bandit_json("not json at all")


def test_missing_results_key_raises() -> None:
    """A malformed/unexpected shape must never silently become zero
    findings -- that would be a dangerous false negative."""
    with pytest.raises(FindingsParseError):
        parse_semgrep_json(json.dumps({"unexpected": "shape"}))
    with pytest.raises(FindingsParseError):
        parse_bandit_json(json.dumps({"unexpected": "shape"}))


def test_malformed_entry_missing_required_field_raises() -> None:
    with pytest.raises(FindingsParseError):
        parse_semgrep_json(json.dumps({"results": [{"path": "app.py"}]}))
    with pytest.raises(FindingsParseError):
        parse_bandit_json(json.dumps({"results": [{"filename": "app.py"}]}))


def test_results_not_a_list_raises() -> None:
    with pytest.raises(FindingsParseError):
        parse_semgrep_json(json.dumps({"results": "not-a-list"}))
