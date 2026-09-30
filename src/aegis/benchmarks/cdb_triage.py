"""Bounded model triage of public-log candidates; never accepts commands."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated

from pydantic import Field, StrictInt

from aegis.domain.base import AegisModel


class TriageSelection(AegisModel):
    selected_ids: tuple[Annotated[StrictInt, Field(ge=0)], ...] = Field(max_length=25)


def selected_timestamps(content: str, timestamps: Sequence[str]) -> tuple[str, ...]:
    selection = TriageSelection.model_validate_json(content)
    ids = selection.selected_ids
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate model-selected IDs")
    if any(index >= len(timestamps) for index in ids):
        raise ValueError("model-selected ID outside the supplied batch")
    return tuple(timestamps[index] for index in ids)
