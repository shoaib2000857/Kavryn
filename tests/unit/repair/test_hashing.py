from __future__ import annotations

from pathlib import Path

from aegis.repair.hashing import hash_source_tree


def test_hash_is_deterministic_across_calls(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "helper.py").write_text("x = 1\n")

    first = hash_source_tree(tmp_path)
    second = hash_source_tree(tmp_path)
    assert first == second


def test_hash_changes_when_content_changes(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n")
    before = hash_source_tree(tmp_path)
    (tmp_path / "app.py").write_text("print('goodbye')\n")
    after = hash_source_tree(tmp_path)
    assert before != after


def test_hash_changes_when_a_file_is_added(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n")
    before = hash_source_tree(tmp_path)
    (tmp_path / "secret.txt").write_text("do not leak\n")
    after = hash_source_tree(tmp_path)
    assert before != after


def test_hash_changes_when_a_file_is_renamed(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n")
    before = hash_source_tree(tmp_path)
    (tmp_path / "app.py").rename(tmp_path / "renamed.py")
    after = hash_source_tree(tmp_path)
    assert before != after


def test_hash_is_independent_of_filesystem_iteration_order(tmp_path: Path) -> None:
    (tmp_path / "z_file.py").write_text("1\n")
    (tmp_path / "a_file.py").write_text("2\n")
    first = hash_source_tree(tmp_path)

    other = tmp_path.parent / (tmp_path.name + "-other")
    other.mkdir()
    (other / "a_file.py").write_text("2\n")
    (other / "z_file.py").write_text("1\n")
    second = hash_source_tree(other)

    assert first == second
