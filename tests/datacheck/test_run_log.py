"""ipi_july_2026_run_log.csv — template structure and behavior inventory."""

from __future__ import annotations

from collections import Counter

from redteam.datacheck import schema as S


def test_column_count_is_19(dataset):
    table = dataset.table("ipi_july_2026_run_log.csv")
    assert len(table.header) == 19
    assert table.header == S.RUN_LOG_SCHEMA.column_names


def test_rows_not_ragged(dataset):
    table = dataset.table("ipi_july_2026_run_log.csv")
    widths = {len(r) for r in table.raw_rows}
    assert widths == {19}, f"ragged rows: widths={widths}"


def test_behavior_count(dataset):
    assert dataset.table("ipi_july_2026_run_log.csv").row_count == 12


def test_behavior_inventory_matches_playbook(dataset):
    found = [
        (row["category"].strip(), row["behavior"].strip())
        for row in dataset.table("ipi_july_2026_run_log.csv").rows
    ]
    assert sorted(found) == sorted(S.RUN_LOG_BEHAVIORS)


def test_category_distribution(dataset):
    counts = Counter(
        row["category"].strip()
        for row in dataset.table("ipi_july_2026_run_log.csv").rows
    )
    assert counts["Coding Agent"] == 4
    assert counts["Computer / Browser Use"] == 3
    assert counts["Tool Use"] == 5


# --- negative mutations ---------------------------------------------------- #
def test_missing_behavior_flagged(mutable_data):
    mutable_data.edit(
        "ipi_july_2026_run_log.csv",
        lambda t: t.replace("Wipe Firmware", "Renamed Behavior", 1),
    )
    assert mutable_data.errors_for("run_log.behavior_inventory")


def test_bad_category_flagged(mutable_data):
    mutable_data.edit(
        "ipi_july_2026_run_log.csv",
        lambda t: t.replace(",Coding Agent,", ",Coding,", 1),
    )
    ids = mutable_data.check_ids()
    assert "ipi_july_2026_run_log.csv.column.category" in ids


def test_wave_must_be_1(dataset):
    for row in dataset.table("ipi_july_2026_run_log.csv").rows:
        assert row["wave"].strip() == "1"


def test_wave_other_than_1_flagged(mutable_data):
    mutable_data.edit(
        "ipi_july_2026_run_log.csv",
        lambda t: t.replace(",1,Coding Agent,", ",2,Coding Agent,", 1),
    )
    assert mutable_data.errors_for("ipi_july_2026_run_log.csv.column.wave")


def test_trailing_comma_regression_flagged(mutable_data):
    # Reintroduce the original defect: a stray trailing comma on every data row.
    def add_comma(t: str) -> str:
        lines = t.splitlines()
        out = [lines[0]] + [l + "," for l in lines[1:]]
        return "\n".join(out) + "\n"

    mutable_data.edit("ipi_july_2026_run_log.csv", add_comma)
    assert mutable_data.errors_for("ipi_july_2026_run_log.csv.ragged_rows")
