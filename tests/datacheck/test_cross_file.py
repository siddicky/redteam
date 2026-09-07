"""Cross-file / doc-vs-data consistency."""

from __future__ import annotations

import re

from redteam.datacheck import schema as S

_CHALLENGE_LINK_RE = re.compile(r"/arena/challenge/([a-z0-9-]+)")


def test_readme_links_every_catalogued_challenge(dataset):
    readme_slugs = set(_CHALLENGE_LINK_RE.findall(dataset.doc("README.md")))
    csv_slugs = {s.strip() for s in dataset.table("arena_challenges.csv").column("slug")}
    assert csv_slugs <= readme_slugs
    # No README challenge link should point at an uncatalogued slug.
    assert readme_slugs <= csv_slugs


def test_playbook_documents_every_run_log_behavior(dataset):
    playbook = dataset.doc("ACTIVE_CHALLENGE_PLAYBOOK.md")
    for _category, behavior in S.RUN_LOG_BEHAVIORS:
        assert behavior in playbook, behavior


def test_readme_mentions_unrecovered_waves(dataset):
    readme = dataset.doc("README.md")
    for wave in S.UNRECOVERED_WAVES:
        assert re.search(rf"\b{wave}\b", readme)


def test_handoff_file_map_files_exist(dataset):
    handoff = dataset.doc("CLAUDE_CODE_HANDOFF.md")
    referenced = set(re.findall(r"`([A-Za-z0-9_./-]+\.(?:csv|md))`", handoff))
    assert referenced, "handoff should reference the data files"
    for fname in referenced:
        base = fname.split("/")[-1]
        assert (dataset.data_dir / base).is_file(), fname


# --- negative mutations ---------------------------------------------------- #
def test_uncatalogued_readme_challenge_flagged(mutable_data):
    mutable_data.edit(
        "README.md",
        lambda t: t + "\nSee /arena/challenge/ghost-challenge for details.\n",
    )
    assert mutable_data.errors_for("cross.readme_challenges")


def test_renamed_catalog_slug_desyncs_readme(mutable_data):
    # Rename a slug in the CSV so the README no longer links it.
    mutable_data.edit(
        "arena_challenges.csv",
        lambda t: t.replace(",cyber-bypass,", ",cyber-bypass-renamed,", 1),
    )
    assert mutable_data.errors_for("cross.readme_challenges")


def test_playbook_missing_behavior_flagged(mutable_data):
    mutable_data.edit(
        "ACTIVE_CHALLENGE_PLAYBOOK.md",
        lambda t: t.replace("Kill Crops", "Redacted Behavior"),
    )
    assert mutable_data.errors_for("cross.playbook_runlog")


def test_wave_writeup_urls_are_in_catalog(dataset):
    waves = dataset.table("proving_ground_waves.csv")
    catalog = {u.strip() for u in dataset.table("public_writeups_walkthroughs.csv").column("url")}
    cited = {u.strip() for u in waves.column("public_writeup") if u.strip()}
    assert cited, "expected some wave rows to cite a writeup URL"
    assert cited <= catalog


def test_orphan_wave_writeup_flagged(mutable_data):
    # Point a wave row at a URL that is not in the writeups catalog.
    def orphan(t: str) -> str:
        lines = t.splitlines()
        for i, l in enumerate(lines[1:], start=1):
            parts = l.split(",")
            if parts[5].strip():  # public_writeup already set
                parts[5] = "https://example.com/not-in-catalog"
                lines[i] = ",".join(parts)
                break
        return "\n".join(lines) + "\n"

    mutable_data.edit("proving_ground_waves.csv", orphan)
    assert mutable_data.errors_for("cross.wave_writeups")
