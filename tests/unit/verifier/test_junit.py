from __future__ import annotations

import pytest

from aegis.verifier.junit import JUnitParseError, parse_junit_xml

PASSING = """<?xml version="1.0"?>
<testsuites><testsuite name="pytest">
<testcase classname="public.test_public" name="test_healthz_ok" time="0.01" />
</testsuite></testsuites>"""

MIXED = """<?xml version="1.0"?>
<testsuites><testsuite name="pytest">
<testcase classname="hidden.test_exploit_replay" name="test_blocked" time="0.01">
<failure message="assert sentinel leaked">traceback...</failure>
</testcase>
<testcase classname="hidden.test_regression" name="test_still_works" time="0.01" />
</testsuite></testsuites>"""

WITH_ERROR = """<?xml version="1.0"?>
<testsuites><testsuite name="pytest">
<testcase classname="public.test_public" name="test_x" time="0.01">
<error message="collection error">boom</error>
</testcase>
</testsuite></testsuites>"""


def test_parses_a_passing_test() -> None:
    outcomes = parse_junit_xml(PASSING)
    assert len(outcomes) == 1
    assert outcomes[0].passed is True
    assert outcomes[0].classname == "public.test_public"


def test_parses_mixed_pass_and_failure() -> None:
    outcomes = parse_junit_xml(MIXED)
    assert len(outcomes) == 2
    by_name = {o.name: o for o in outcomes}
    assert by_name["test_blocked"].passed is False
    assert "sentinel leaked" in by_name["test_blocked"].message
    assert by_name["test_still_works"].passed is True


def test_error_element_is_treated_as_not_passed() -> None:
    outcomes = parse_junit_xml(WITH_ERROR)
    assert outcomes[0].passed is False


def test_malformed_xml_raises() -> None:
    with pytest.raises(JUnitParseError):
        parse_junit_xml("not xml at all <<<")


def test_empty_testsuite_returns_no_outcomes() -> None:
    empty = '<?xml version="1.0"?><testsuites><testsuite name="pytest"></testsuite></testsuites>'
    assert parse_junit_xml(empty) == ()
