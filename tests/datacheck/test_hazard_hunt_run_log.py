"""hazard_hunt_q3_run_log.csv — template structure and behavior inventory."""

from __future__ import annotations

from redteam.datacheck import schema as S


def test_template_has_exactly_40_lines_and_20_columns(dataset):
    table = dataset.table("hazard_hunt_q3_run_log.csv")
    assert len(table.raw_rows) + 1 == 40
    assert table.header == S.HAZARD_HUNT_RUN_LOG_SCHEMA.column_names
    assert {len(row) for row in table.raw_rows} == {20}


def test_behavior_inventory_matches_canonical_order(dataset):
    found = [
        (row["category"].strip(), row["behavior_slug"].strip(), row["behavior_name"].strip())
        for row in dataset.table("hazard_hunt_q3_run_log.csv").rows
    ]
    assert found == list(S.HAZARD_HUNT_BEHAVIORS)


def test_category_schema_accepts_only_hazard_hunt_categories():
    assert S.HAZARD_HUNT_RUN_LOG_SCHEMA.column("category").enum == frozenset(
        {"Chemistry", "Biology", "Misc", "Cyber"}
    )


def test_reordered_behavior_rows_flagged(mutable_data):
    def reorder(t: str) -> str:
        lines = t.splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        return "\n".join(lines) + "\n"

    mutable_data.edit("hazard_hunt_q3_run_log.csv", reorder)
    assert mutable_data.errors_for("hazard_hunt_run_log.behavior_inventory")


def test_hazard_hunt_playbook_is_loaded(dataset):
    assert "HAZARD_HUNT_PLAYBOOK.md" in dataset.docs


def test_playbook_documents_every_behavior(dataset):
    # Mirror of cross.playbook_runlog: the field kit must name every behavior
    # the run-log template carries, so neither file can drift from the other.
    playbook = dataset.doc("HAZARD_HUNT_PLAYBOOK.md")
    for category, slug, name in S.HAZARD_HUNT_BEHAVIORS:
        assert f"### {category}" in playbook
        assert slug in playbook, f"{slug!r} ({category}) missing from HAZARD_HUNT_PLAYBOOK.md"
        assert name in playbook
