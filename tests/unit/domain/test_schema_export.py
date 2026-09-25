from __future__ import annotations

from aegis.schema_export import SCHEMAS_DIR, generate


def test_committed_schemas_match_generated_output() -> None:
    """Guards against model/schema drift: schemas/*.json must always be
    regenerable byte-for-byte from the current domain models."""
    rendered = generate()
    assert rendered, "expected at least one schema to be generated"
    for filename, text in rendered.items():
        path = SCHEMAS_DIR / filename
        assert path.exists(), (
            f"missing committed schema: {filename} (run scripts/export_schemas.py)"
        )
        assert path.read_text() == text, (
            f"schema out of date: {filename} (run scripts/export_schemas.py)"
        )


def test_no_stray_schema_files_are_committed() -> None:
    rendered = generate()
    on_disk = {p.name for p in SCHEMAS_DIR.glob("*.json")}
    assert on_disk == set(rendered), "schemas/ contains files not produced by any registered model"
