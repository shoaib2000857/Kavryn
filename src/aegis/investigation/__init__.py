"""Defensive investigation helpers built from normalized, scoped evidence."""

from aegis.investigation.correlation import (
    CorrelationReport,
    InvestigationHypothesis,
    RouteSourceBinding,
    correlate_evidence,
)
from aegis.investigation.range import RangeEvidenceInvestigator, make_range_semgrep_adapter

__all__ = [
    "CorrelationReport",
    "InvestigationHypothesis",
    "RangeEvidenceInvestigator",
    "RouteSourceBinding",
    "correlate_evidence",
    "make_range_semgrep_adapter",
]
