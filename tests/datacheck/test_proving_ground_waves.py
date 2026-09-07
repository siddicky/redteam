"""proving_ground_waves.csv — positive invariants and negative mutation tests."""

from __future__ import annotations

from collections import defaultdict

from redteam.datacheck import schema as S


def _by_wave(table):
    published = defaultdict(set)
    gaps = set()
    for row in table.rows:
        wave = int(row["wave"])
        if row["live_visibility"].strip() == "not_recovered":
            gaps.add(wave)
        elif row["category"] in S.PROVING_GROUND_CATEGORIES:
            published[wave].add(row["category"])
    return published, gaps


def test_row_count(dataset):
    assert dataset.table("proving_ground_waves.csv").row_count == 95


def test_all_waves_1_to_26_present(dataset):
    waves = {int(v) for v in dataset.table("proving_ground_waves.csv").column("wave")}
    assert waves == set(range(1, S.PROVING_GROUND_MAX_WAVE + 1))


def test_unrecovered_waves_are_gaps(dataset):
    _, gaps = _by_wave(dataset.table("proving_ground_waves.csv"))
    assert gaps == set(S.UNRECOVERED_WAVES)


def test_published_waves_have_four_categories(dataset):
    published, _ = _by_wave(dataset.table("proving_ground_waves.csv"))
    assert len(published) == S.EXPECTED_PUBLISHED_WAVES
    for wave, cats in published.items():
        assert cats == S.PROVING_GROUND_CATEGORIES, f"wave {wave}: {cats}"


def test_gap_rows_have_empty_slug(dataset):
    for row in dataset.table("proving_ground_waves.csv").rows:
        if row["live_visibility"].strip() == "not_recovered":
            assert row["behavior_slug"].strip() == ""
            assert row["category"].strip() == S.GAP_CATEGORY


def test_archived_rows_are_waves_1_and_4(dataset):
    archived = {
        int(row["wave"])
        for row in dataset.table("proving_ground_waves.csv").rows
        if row["live_visibility"].strip() == "archived"
    }
    assert archived == set(S.ARCHIVED_WAVES)


# --- negative mutations ---------------------------------------------------- #
def test_missing_category_flagged_without_changing_row_count(mutable_data):
    # Turn wave 2's Image row into a duplicate Chat row: row count stays 95, but
    # wave 2 now has only 3 distinct categories. Only wave_categories can fire.
    def dupe_category(t: str) -> str:
        lines = t.splitlines()
        for i, l in enumerate(lines):
            if l.startswith("2,Image,"):
                parts = l.split(",")
                parts[1] = "Chat"
                lines[i] = ",".join(parts)
                break
        return "\n".join(lines) + "\n"

    mutable_data.edit("proving_ground_waves.csv", dupe_category)
    assert mutable_data.report().findings  # something fired
    assert mutable_data.errors_for("proving_ground.wave_categories")
    # And it was NOT the row-count arm doing the work.
    assert not mutable_data.errors_for("proving_ground_waves.csv.row_count")


def test_gap_row_with_category_flagged(mutable_data):
    # not_recovered row must use category 'Unknown'; give wave 7 a real category.
    mutable_data.edit(
        "proving_ground_waves.csv",
        lambda t: t.replace(
            "7,Unknown,,not_recovered,", "7,Chat,,not_recovered,"
        ),
    )
    assert mutable_data.errors_for("proving_ground.gap_shape")


def test_live_row_with_unknown_category_flagged(mutable_data):
    # 'Unknown' is only valid on not_recovered rows.
    def corrupt(t: str) -> str:
        lines = t.splitlines()
        for i, l in enumerate(lines[1:], start=1):
            parts = l.split(",")
            if parts[3] == "live":
                parts[1] = "Unknown"
                lines[i] = ",".join(parts)
                break
        return "\n".join(lines) + "\n"

    mutable_data.edit("proving_ground_waves.csv", corrupt)
    assert mutable_data.errors_for("proving_ground.gap_shape")


def test_removing_published_wave_rows_drops_count(mutable_data):
    # Delete all four rows of published wave 12; row count changes too, but the
    # published-wave-count check must now observe 22 published waves and fire.
    def drop_wave(t: str) -> str:
        lines = t.splitlines()
        kept = [lines[0]] + [l for l in lines[1:] if not l.startswith("12,")]
        return "\n".join(kept) + "\n"

    mutable_data.edit("proving_ground_waves.csv", drop_wave)
    assert mutable_data.errors_for("proving_ground.published_wave_count")


def test_recovering_a_gap_wave_flagged(mutable_data):
    # Turn the wave-7 gap marker into a bogus live row.
    mutable_data.edit(
        "proving_ground_waves.csv",
        lambda t: t.replace(
            "7,Unknown,,not_recovered,live UI and available archives,",
            "7,Chat,some-slug,live,Arena,",
        ),
    )
    assert mutable_data.errors_for("proving_ground.unrecovered_waves")


def test_bad_visibility_flagged(mutable_data):
    mutable_data.edit(
        "proving_ground_waves.csv", lambda t: t.replace(",live,", ",LIVE,", 1)
    )
    assert mutable_data.errors_for("proving_ground_waves.csv.column.live_visibility")


def test_published_row_missing_slug_flagged(mutable_data):
    # Blank the slug on the first live row while keeping it non-gap.
    def blank(t: str) -> str:
        lines = t.splitlines()
        for i, l in enumerate(lines[1:], start=1):
            parts = l.split(",")
            if parts[3] == "live":
                parts[2] = ""
                lines[i] = ",".join(parts)
                break
        return "\n".join(lines) + "\n"

    mutable_data.edit("proving_ground_waves.csv", blank)
    assert mutable_data.errors_for("proving_ground.missing_slug")
