"""Parsing of pytest's JUnit XML output from inside the verifier container.

Tool output is untrusted (SR-INJ-001) even when it comes from a pinned
tool this project ran itself: this only ever extracts a bounded
pass/fail/error summary per test case, never anything treated as an
instruction. ``xml.etree.ElementTree`` does not resolve external
entities in CPython, so it is safe against XXE for this bounded,
internally-generated input.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from aegis.domain.base import AegisModel

__all__ = ["JUnitParseError", "TestOutcome", "parse_junit_xml"]


class JUnitParseError(ValueError):
    """Raised when verifier output is not well-formed JUnit XML."""


class TestOutcome(AegisModel):
    classname: str
    name: str
    passed: bool
    message: str


def parse_junit_xml(xml_text: str) -> tuple[TestOutcome, ...]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise JUnitParseError(f"verifier output is not valid JUnit XML: {exc}") from exc

    outcomes = []
    for testcase in root.iter("testcase"):
        classname = testcase.get("classname", "")
        name = testcase.get("name", "")
        failure = testcase.find("failure")
        error = testcase.find("error")
        if failure is not None:
            outcomes.append(
                TestOutcome(
                    classname=classname,
                    name=name,
                    passed=False,
                    message=failure.get("message", "failed"),
                )
            )
        elif error is not None:
            outcomes.append(
                TestOutcome(
                    classname=classname,
                    name=name,
                    passed=False,
                    message=error.get("message", "error"),
                )
            )
        else:
            outcomes.append(
                TestOutcome(classname=classname, name=name, passed=True, message="passed")
            )
    return tuple(outcomes)
