"""arena_challenges.csv — positive invariants and negative mutation tests."""

from __future__ import annotations

from collections import Counter

from redteam.datacheck import schema as S


def test_row_count(dataset):
    assert dataset.table("arena_challenges.csv").row_count == S.EXPECTED_CHALLENGE_COUNT


def test_header(dataset):
    assert (
        dataset.table("arena_challenges.csv").header
        == S.ARENA_CHALLENGES_SCHEMA.column_names
    )


def test_status_distribution(dataset):
    statuses = Counter(
        v.strip() for v in dataset.table("arena_challenges.csv").column("status_2026_09_03")
    )
    completed = sum(statuses[s] for s in S.COMPLETED_STATUSES)
    ongoing = sum(statuses[s] for s in S.ONGOING_STATUSES)
    assert completed == S.EXPECTED_COMPLETED
    assert ongoing == S.EXPECTED_ONGOING


def test_catalog_order_is_1_to_27(dataset):
    orders = [int(v) for v in dataset.table("arena_challenges.csv").column("catalog_order")]
    assert orders == list(range(1, S.EXPECTED_CHALLENGE_COUNT + 1))


def test_slugs_unique(dataset):
    slugs = dataset.table("arena_challenges.csv").column("slug")
    assert len(slugs) == len(set(slugs))


def test_ongoing_slugs_present(dataset):
    slugs = {v.strip() for v in dataset.table("arena_challenges.csv").column("slug")}
    assert S.ONGOING_SLUGS <= slugs


def test_hazard_hunt_q3_row(dataset):
    rows = dataset.table("arena_challenges.csv").rows
    hazard_hunt = next(row for row in rows if row["slug"] == "hazard-hunt-q3")
    assert hazard_hunt["status_2026_09_03"] == "ongoing"
    assert hazard_hunt["prize_usd"] == "80000"


# --- negative mutations ---------------------------------------------------- #
def test_bad_status_flagged(mutable_data):
    mutable_data.edit(
        "arena_challenges.csv", lambda t: t.replace(",ongoing,", ",LIVE,", 1)
    )
    assert mutable_data.errors_for("arena_challenges.csv.column.status_2026_09_03")


def test_extra_row_breaks_counts(mutable_data):
    mutable_data.edit(
        "arena_challenges.csv",
        lambda t: t.rstrip("\n")
        + "\n28,extra-slug,Extra,completed,0,none,\n",
    )
    ids = mutable_data.check_ids()
    assert "arena_challenges.csv.row_count" in ids


def test_duplicate_slug_flagged(mutable_data):
    def dup(t: str) -> str:
        lines = t.splitlines()
        # Change the slug on the last row to collide with the first data row.
        first_slug = lines[1].split(",")[1]
        parts = lines[-1].split(",")
        parts[1] = first_slug
        lines[-1] = ",".join(parts)
        return "\n".join(lines) + "\n"

    mutable_data.edit("arena_challenges.csv", dup)
    assert mutable_data.errors_for("arena_challenges.csv.unique.slug")


def test_non_integer_prize_flagged(mutable_data):
    mutable_data.edit(
        "arena_challenges.csv", lambda t: t.replace(",20000,", ",$20k,", 1)
    )
    assert mutable_data.errors_for("arena_challenges.csv.column.prize_usd")


def test_status_flip_trips_count_checks(mutable_data):
    # Flip one 'completed' to 'ongoing_practice' WITHOUT changing the row count,
    # so the row-count-gated count checks actually run and both fire.
    mutable_data.edit(
        "arena_challenges.csv",
        lambda t: t.replace(",completed,", ",ongoing_practice,", 1),
    )
    assert mutable_data.errors_for("arena_challenges.completed_count")
    assert mutable_data.errors_for("arena_challenges.ongoing_count")
    # Confirm the row count itself was untouched (the checks weren't skipped).
    assert not mutable_data.errors_for("arena_challenges.csv.row_count")
