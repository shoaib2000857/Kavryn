"""Structured-output parsing and bounded repair.

See docs/MODEL_STRATEGY.md "Structured-output rule":

1. preserve the original response as an artifact;
2. allow at most a bounded repair attempt;
3. never infer an action from free-form text; and
4. refuse/escalate if a safe typed proposal cannot be obtained.

``parse_structured_proposal`` only ever accepts well-formed JSON that
validates against ``StructuredProposal`` — there is no heuristic
free-text fallback. ``parse_with_bounded_repair`` preserves every raw
response it saw on ``ProposalParseError.attempts`` and calls the
caller-supplied ``repair`` function at most ``max_repair_attempts``
times before giving up, so a caller can store the raw artifacts and
refuse/escalate rather than guess.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from pydantic import ValidationError

from aegis.providers.schemas import StructuredProposal

__all__ = [
    "ProposalParseError",
    "RepairFn",
    "parse_structured_proposal",
    "parse_with_bounded_repair",
]

RepairFn = Callable[[str, str], str]


class ProposalParseError(ValueError):
    """Raised when raw model output cannot be parsed as a ``StructuredProposal``.

    ``attempts`` preserves every raw response text that was tried, in
    order, so the caller can store them as artifacts even after giving
    up (docs/MODEL_STRATEGY.md rule 1).
    """

    def __init__(self, message: str, *, attempts: tuple[str, ...]) -> None:
        super().__init__(message)
        self.attempts = attempts


def parse_structured_proposal(raw: str) -> StructuredProposal:
    """Parse ``raw`` JSON text into a ``StructuredProposal``, or fail.

    Never falls back to inferring a proposal from free-form text: a
    non-JSON or schema-invalid response is always a hard parse failure.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProposalParseError(f"response is not valid JSON: {exc}", attempts=(raw,)) from exc
    try:
        return StructuredProposal.model_validate(data)
    except ValidationError as exc:
        raise ProposalParseError(
            f"response does not match the structured-proposal schema: {exc}", attempts=(raw,)
        ) from exc


def parse_with_bounded_repair(
    raw: str,
    *,
    repair: RepairFn | None = None,
    max_repair_attempts: int = 1,
) -> StructuredProposal:
    """Parse ``raw``, retrying via ``repair`` at most ``max_repair_attempts`` times.

    ``repair(raw_response, error_message)`` must return a corrected raw
    response string (e.g. by re-querying the model with the error as
    corrective instruction) — it is the caller's responsibility, not
    this function's, to make that call; ``parse_with_bounded_repair``
    only bounds and sequences the attempts. If ``repair`` is ``None`` or
    the bound is exhausted, the last ``ProposalParseError`` propagates
    with every attempted raw response recorded on ``.attempts``.
    """
    attempts: list[str] = []
    current = raw
    remaining = max_repair_attempts
    while True:
        attempts.append(current)
        try:
            return parse_structured_proposal(current)
        except ProposalParseError as exc:
            if repair is None or remaining <= 0:
                raise ProposalParseError(str(exc), attempts=tuple(attempts)) from exc
            current = repair(current, str(exc))
            remaining -= 1
