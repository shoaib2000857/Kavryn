from __future__ import annotations

import ast
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[3] / "src" / "aegis" / "core"
FORBIDDEN_CORE_IMPORTS = frozenset(
    {
        "aegis.range",
        "aegis.orchestrator",
        "aegis.telemetry",
        "aegis.repair",
        "aegis.verifier",
        "aegis.workers",
        "aegis.tools",
        "aegis.providers",
    }
)


def test_core_runtime_does_not_import_cyber_defender_packages() -> None:
    imports: set[str] = set()
    for source_path in CORE_DIR.glob("*.py"):
        tree = ast.parse(source_path.read_text(), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imports.add(node.module)

    violations = {
        imported
        for imported in imports
        if any(
            imported == forbidden or imported.startswith(f"{forbidden}.")
            for forbidden in FORBIDDEN_CORE_IMPORTS
        )
    }
    assert not violations, f"runtime core imports cyber-specific packages: {sorted(violations)}"
