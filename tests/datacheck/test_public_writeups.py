"""public_writeups_walkthroughs.csv — positive invariants and mutations."""

from __future__ import annotations

from redteam.datacheck import schema as S


def test_row_count(dataset):
    assert dataset.table("public_writeups_walkthroughs.csv").row_count == S.EXPECTED_WRITEUP_COUNT


def test_ids_sequential(dataset):
    ids = [int(v) for v in dataset.table("public_writeups_walkthroughs.csv").column("id")]
    assert ids == list(range(1, S.EXPECTED_WRITEUP_COUNT + 1))


def test_urls_unique(dataset):
    urls = dataset.table("public_writeups_walkthroughs.csv").column("url")
    assert len(urls) == len(set(urls))


def test_urls_are_http(dataset):
    for url in dataset.table("public_writeups_walkthroughs.csv").column("url"):
        assert url.startswith(("http://", "https://")), url


def test_all_public(dataset):
    statuses = set(dataset.table("public_writeups_walkthroughs.csv").column("public_status"))
    assert statuses == {"public"}


def test_dates_well_formed(dataset):
    import re

    rx = re.compile(rf"(?:{S.DATE_RE})\Z")
    for d in dataset.table("public_writeups_walkthroughs.csv").column("date"):
        d = d.strip()
        if d:
            assert rx.match(d), d


# --- negative mutations ---------------------------------------------------- #
def test_duplicate_url_flagged(mutable_data):
    def dup(t: str) -> str:
        lines = t.splitlines()
        first_url = lines[1].split(",")[2]
        parts = lines[-1].split(",")
        parts[2] = first_url
        lines[-1] = ",".join(parts)
        return "\n".join(lines) + "\n"

    mutable_data.edit("public_writeups_walkthroughs.csv", dup)
    assert mutable_data.errors_for("public_writeups_walkthroughs.csv.unique.url")


def test_non_url_flagged(mutable_data):
    mutable_data.edit(
        "public_writeups_walkthroughs.csv",
        lambda t: t.replace("https://www.grayswan.ai/blog/gray-swan-arena", "not-a-url", 1),
    )
    assert mutable_data.errors_for("public_writeups_walkthroughs.csv.column.url")


def test_bad_public_status_flagged(mutable_data):
    mutable_data.edit(
        "public_writeups_walkthroughs.csv", lambda t: t.replace(",public,", ",private,", 1)
    )
    assert mutable_data.errors_for("public_writeups_walkthroughs.csv.column.public_status")


def test_malformed_date_flagged(mutable_data):
    mutable_data.edit(
        "public_writeups_walkthroughs.csv",
        lambda t: t.replace(",2024-10-28,", ",October 2024,", 1),
    )
    assert mutable_data.errors_for("public_writeups_walkthroughs.csv.column.date")
