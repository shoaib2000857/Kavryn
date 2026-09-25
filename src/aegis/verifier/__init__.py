"""The clean-room verifier and assurance gate (docs/IMPLEMENTATION_HANDOFF.md Change 6).

This package never imports from ``aegis.repair``'s workspace/patch-
application code path and never imports any provider/model code
(docs/TOOLS_AND_SANDBOXES.md "Clean-room verifier": "no model access").
"""

from aegis.verifier.checks import (
    check_clean_room_tests,
    check_diff_policy,
    check_security_rescan,
    check_source_integrity,
)
from aegis.verifier.gate import evaluate_assurance
from aegis.verifier.junit import JUnitParseError, TestOutcome, parse_junit_xml
from aegis.verifier.models import AssuranceBundle, AssuranceOutcome, CheckResult, CheckStatus

__all__ = [
    "AssuranceBundle",
    "AssuranceOutcome",
    "CheckResult",
    "CheckStatus",
    "JUnitParseError",
    "TestOutcome",
    "check_clean_room_tests",
    "check_diff_policy",
    "check_security_rescan",
    "check_source_integrity",
    "evaluate_assurance",
    "parse_junit_xml",
]
