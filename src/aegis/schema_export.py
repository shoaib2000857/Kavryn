"""Generate versioned JSON Schema documents for every registered domain model.

Used by ``scripts/export_schemas.py`` (the developer/CI entrypoint) and by
``tests/unit/domain/test_schema_export.py`` (drift detection).
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis.domain.registry import SCHEMA_REGISTRY

SCHEMAS_DIR = Path(__file__).resolve().parent.parent.parent / "schemas"

__all__ = ["SCHEMAS_DIR", "generate"]


def _filename(schema_version: str) -> str:
    return schema_version.replace("/", ".") + ".json"


def generate() -> dict[str, str]:
    """Return {filename: rendered JSON schema text} for every registered model."""
    rendered: dict[str, str] = {}
    for schema_version, model in sorted(SCHEMA_REGISTRY.items()):
        schema = model.model_json_schema()
        text = json.dumps(schema, indent=2, sort_keys=True) + "\n"
        rendered[_filename(schema_version)] = text
    return rendered
