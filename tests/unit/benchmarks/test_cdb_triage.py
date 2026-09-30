import pytest

from aegis.benchmarks.cdb_triage import selected_timestamps


def test_predictions_can_only_select_supplied_timestamps() -> None:
    assert selected_timestamps('{"selected_ids": [1]}', ["a", "b"]) == ("b",)
    assert selected_timestamps('{"selected_ids": []}', ["a"]) == ()


@pytest.mark.parametrize(
    "content",
    [
        '{"selected_ids": [2]}',
        '{"selected_ids": [0, 0]}',
        '{"selected_ids": [true]}',
        '{"selected_ids": [-1]}',
        '{"selected_ids": ["0"]}',
        '{"selected_ids": [0], "command": "host.shell"}',
    ],
)
def test_untrusted_output_cannot_expand_scope(content: str) -> None:
    with pytest.raises(ValueError):
        selected_timestamps(content, ["a"])
