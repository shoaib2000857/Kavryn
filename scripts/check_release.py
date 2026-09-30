"""Inspect built distributions without extracting or executing archive contents."""

from __future__ import annotations

import argparse
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


def validate_members(names: list[str], *, wheel: bool) -> None:
    """Reject accidental private/cache payloads and require attribution files."""
    if not names:
        raise ValueError("archive is empty")
    for name in names:
        parts = PurePosixPath(name).parts
        if name.startswith("/") or ".." in parts:
            raise ValueError("unsafe archive path")
        if any(
            part.startswith(".env")
            or part
            in {
                ".git",
                ".bench",
                ".venv",
                ".kavryn-venv",
                "artifacts",
                "__pycache__",
            }
            for part in parts
        ) or name.endswith((".sqlite3", ".pyc", ".pem", ".key")):
            raise ValueError("private/cache payload in distribution")
        if wheel and parts[0] not in {"aegis", "kavryn"} and not parts[0].endswith(".dist-info"):
            raise ValueError("unexpected wheel payload")
    for required in ("LICENSE", "NOTICE"):
        if not any(PurePosixPath(name).name == required for name in names):
            raise ValueError(f"distribution missing {required}")
    for required in ("kavryn/__init__.py", "kavryn/py.typed", "aegis/py.typed"):
        if not any(name.endswith(required) for name in names):
            raise ValueError(f"distribution missing {required}")


def check(directory: Path) -> tuple[str, ...]:
    archives = sorted(directory.glob("*.whl")) + sorted(directory.glob("*.tar.gz"))
    if not any(p.suffix == ".whl" for p in archives) or not any(
        p.name.endswith(".tar.gz") for p in archives
    ):
        raise ValueError("build both a wheel and source distribution first")
    for path in archives:
        if path.suffix == ".whl":
            with zipfile.ZipFile(path) as wheel:
                validate_members(wheel.namelist(), wheel=True)
        else:
            with tarfile.open(path, "r:gz") as source:
                if any(not (member.isfile() or member.isdir()) for member in source.getmembers()):
                    raise ValueError("source archive contains links or special objects")
                validate_members(source.getnames(), wheel=False)
    return tuple(path.name for path in archives)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=Path("dist"))
    args = parser.parse_args()
    for name in check(args.directory):
        print(f"Archive contents checked: {name}")


if __name__ == "__main__":
    main()
