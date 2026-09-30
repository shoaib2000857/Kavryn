"""Pure source-span reconstruction and canonical whole-file diff construction."""

from __future__ import annotations

from difflib import unified_diff
from pathlib import PurePosixPath

from pydantic import Field, model_validator

from aegis.domain.base import AegisModel


class SourceSpan(AegisModel):
    """One-based inclusive line range, selected by trusted source localization."""

    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)

    @model_validator(mode="after")
    def _ordered(self) -> SourceSpan:
        if self.end_line < self.start_line:
            raise ValueError("source span is reversed")
        return self

    def select(self, source: str) -> str:
        lines = source.splitlines(keepends=True)
        if self.end_line > len(lines):
            raise ValueError("source span exceeds the trusted file")
        return "".join(lines[self.start_line - 1 : self.end_line])

    def replace(self, source: str, replacement: str) -> str:
        selected = self.select(source)
        if replacement.endswith("\n") != selected.endswith("\n"):
            raise ValueError("replacement changed the source span's newline convention")
        lines = source.splitlines(keepends=True)
        return "".join(lines[: self.start_line - 1]) + replacement + "".join(lines[self.end_line :])


def canonical_source_diff(path: str, original: str, updated: str) -> str:
    """Return a whole-file unified diff including missing-final-newline markers.

    No filesystem writes or commands occur here. Caller still applies scope and
    independent verification; constructing a valid diff does not prove a repair.
    """
    parts = PurePosixPath(path).parts
    if (
        not parts
        or path.startswith("/")
        or any(p in (".", "..") for p in path.split("/"))
        or any(c in path for c in ("\\", "\t", "\n", "\r", "\0", '"'))
    ):
        raise ValueError("source path is not a safe relative POSIX path")
    result: list[str] = []
    for line in unified_diff(
        original.splitlines(keepends=True),
        updated.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    ):
        if line.endswith("\n"):
            result.append(line)
        else:
            result.extend((line + "\n", "\\ No newline at end of file\n"))
    return "".join(result)
