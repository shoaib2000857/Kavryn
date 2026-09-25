"""Typed static-analysis adapters (docs/IMPLEMENTATION_HANDOFF.md Change 5)."""

from aegis.tools.findings import (
    FindingsParseError,
    NormalizedFinding,
    parse_bandit_json,
    parse_semgrep_json,
)
from aegis.tools.static_analysis import (
    DEFAULT_SEMGREP_RULESET,
    ContainerStaticAnalysisAdapter,
    make_bandit_adapter,
    make_semgrep_adapter,
)

__all__ = [
    "DEFAULT_SEMGREP_RULESET",
    "ContainerStaticAnalysisAdapter",
    "FindingsParseError",
    "NormalizedFinding",
    "make_bandit_adapter",
    "make_semgrep_adapter",
    "parse_bandit_json",
    "parse_semgrep_json",
]
