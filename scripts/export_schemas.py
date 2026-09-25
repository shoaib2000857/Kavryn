"""CLI entrypoint: write versioned JSON Schema documents to schemas/.

Usage:
    python scripts/export_schemas.py [--check]

Writes one file per schema version under ``schemas/``, named after the
``schema_version`` string (e.g. ``schemas/aegis.case.v1.json``). With
``--check``, exits non-zero instead of writing if the generated content
would differ from what is already on disk, so drift between the models
and the committed schemas is caught in CI.
"""

from __future__ import annotations

import argparse
import sys

from aegis.schema_export import SCHEMAS_DIR, generate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify committed schemas match generated output without writing",
    )
    args = parser.parse_args()

    rendered = generate()

    if args.check:
        stale = [
            filename
            for filename, text in rendered.items()
            if not (SCHEMAS_DIR / filename).exists() or (SCHEMAS_DIR / filename).read_text() != text
        ]
        if stale:
            print("schemas out of date, run scripts/export_schemas.py:", file=sys.stderr)
            for filename in stale:
                print(f"  - {filename}", file=sys.stderr)
            return 1
        print(f"{len(rendered)} schema(s) up to date")
        return 0

    SCHEMAS_DIR.mkdir(parents=True, exist_ok=True)
    for filename, text in rendered.items():
        (SCHEMAS_DIR / filename).write_text(text)
    print(f"wrote {len(rendered)} schema(s) to {SCHEMAS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
