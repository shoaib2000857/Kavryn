"""The reversible-containment rule and its file-based enforcement point.

See docs/DECISIONS.md ADR-029: a "proxy rule" was chosen, experimentally,
as the reversible-containment primitive for the first range
(docs/OPEN_QUESTIONS.md's engineering question). Applying containment
and rolling it back are the same operation -- writing a
``ContainmentRule`` -- so rollback cannot drift from apply: it is
simply applying the rule captured before containment began.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis.domain.base import AegisModel

__all__ = ["ContainmentRule", "read_rules", "write_rules"]


class ContainmentRule(AegisModel):
    deny_query_patterns: tuple[str, ...] = ()
    deny_authorization_patterns: tuple[str, ...] = ()


def write_rules(path: str, rule: ContainmentRule) -> None:
    Path(path).write_text(
        json.dumps(
            {
                "deny_query_patterns": list(rule.deny_query_patterns),
                "deny_authorization_patterns": list(rule.deny_authorization_patterns),
            }
        )
    )


def read_rules(path: str) -> ContainmentRule:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return ContainmentRule()
    patterns = data.get("deny_query_patterns") if isinstance(data, dict) else None
    authorization_patterns = (
        data.get("deny_authorization_patterns", []) if isinstance(data, dict) else []
    )
    if (
        not isinstance(patterns, list)
        or any(not isinstance(pattern, str) for pattern in patterns)
        or not isinstance(authorization_patterns, list)
        or any(not isinstance(pattern, str) for pattern in authorization_patterns)
    ):
        return ContainmentRule()
    return ContainmentRule(
        deny_query_patterns=tuple(patterns),
        deny_authorization_patterns=tuple(authorization_patterns),
    )
