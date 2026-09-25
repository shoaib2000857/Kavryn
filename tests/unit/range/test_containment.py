from __future__ import annotations

from pathlib import Path

from aegis.range.containment import ContainmentRule, read_rules, write_rules


def test_write_then_read_round_trips(tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.json"
    write_rules(str(rules_file), ContainmentRule(deny_query_patterns=(r"\.\.",)))
    assert read_rules(str(rules_file)) == ContainmentRule(deny_query_patterns=(r"\.\.",))


def test_missing_file_defaults_to_no_containment(tmp_path: Path) -> None:
    assert read_rules(str(tmp_path / "does-not-exist.json")) == ContainmentRule()


def test_malformed_json_defaults_to_no_containment(tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.json"
    rules_file.write_text("not json at all")
    assert read_rules(str(rules_file)) == ContainmentRule()


def test_wrong_shape_defaults_to_no_containment(tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.json"
    rules_file.write_text('{"deny_query_patterns": "not-a-list"}')
    assert read_rules(str(rules_file)) == ContainmentRule()


def test_rollback_is_just_applying_the_prior_rule(tmp_path: Path) -> None:
    """Rollback has no separate code path from apply -- it cannot drift."""
    rules_file = tmp_path / "rules.json"
    original = ContainmentRule()
    write_rules(str(rules_file), ContainmentRule(deny_query_patterns=(r"\.\.",)))
    assert read_rules(str(rules_file)).deny_query_patterns != ()
    write_rules(str(rules_file), original)
    assert read_rules(str(rules_file)) == original
