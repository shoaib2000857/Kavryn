"""Case reporting: machine-readable JSON and a human-readable summary.

See docs/PRODUCT_REQUIREMENTS.md FR-RPT-001: "Export machine-readable
JSON and SARIF where applicable, plus a human-readable case report."
SARIF export belongs with the static-analysis findings already produced
in Change 5 (``aegis.tools.findings``), not the case-level report
itself, and is out of scope here.
"""

from __future__ import annotations

import json
from typing import Any

from aegis.orchestrator.case_runner import CaseTrace

__all__ = ["render_human_report", "render_json_report"]


def render_json_report(trace: CaseTrace) -> str:
    payload: dict[str, Any] = {
        "case_id": trace.case_id,
        "final_state": trace.final_state.value,
        "halted": trace.halted,
        "halt_reason": trace.halt_reason,
        "states": [state.value for state in trace.states],
        "notes": list(trace.notes),
    }
    return json.dumps(payload, indent=2)


def render_human_report(trace: CaseTrace) -> str:
    lines = [f"# Case {trace.case_id}", ""]
    if trace.halted:
        lines.append(f"**Outcome:** halted at `{trace.final_state.value}` — {trace.halt_reason}")
    else:
        lines.append(f"**Outcome:** completed at `{trace.final_state.value}`")
    lines.append("")
    lines.append("## Timeline")
    for state, note in zip(trace.states, trace.notes, strict=True):
        lines.append(f"- `{state.value}` — {note}")
    return "\n".join(lines) + "\n"
