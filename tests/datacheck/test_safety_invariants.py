"""Safety layer — enforces the handoff's data-handling rule.

These are the highest-value tests: they prove the framework refuses to let
embargoed working strings, credentials, or PII be committed, and that the
safety guidance in the playbook cannot be silently removed.
"""

from __future__ import annotations


# --- positive: shipped compilation is safe --------------------------------- #
def test_no_secrets_in_shipped_data(full_report):
    assert not [f for f in full_report.findings if f.check == "safety.secrets"]


def test_no_unexpected_files_in_shipped_data(full_report):
    assert not [f for f in full_report.findings if f.check == "safety.unexpected_files"]


def test_gitignore_rule_present_in_shipped_repo(full_report):
    assert not [f for f in full_report.findings if f.check == "safety.gitignore"]


def test_run_log_ships_blank(full_report):
    assert not [f for f in full_report.findings if f.check == "safety.run_log_blank"]


def test_embargo_notice_present(full_report):
    assert not [f for f in full_report.findings if f.check == "safety.embargo_notice"]


def test_no_unexpected_pii(full_report):
    assert not [f for f in full_report.findings if f.check == "safety.pii"]


# --- negative: the guards actually fire ------------------------------------ #
def test_committed_payload_in_run_log_flagged(mutable_data):
    # Simulate someone pasting a working string into the committed template.
    def populate(t: str) -> str:
        lines = t.splitlines()
        parts = lines[1].split(",")
        parts[-1] = "candidate: <a working break string here>"  # private_payload_location
        lines[1] = ",".join(parts)
        return "\n".join(lines) + "\n"

    mutable_data.edit("ipi_july_2026_run_log.csv", populate)
    assert mutable_data.errors_for("safety.run_log_blank")


def test_credited_cell_populated_flagged(mutable_data):
    def populate(t: str) -> str:
        lines = t.splitlines()
        parts = lines[1].split(",")
        parts[17] = "yes"  # credited_cell column
        lines[1] = ",".join(parts)
        return "\n".join(lines) + "\n"

    mutable_data.edit("ipi_july_2026_run_log.csv", populate)
    assert mutable_data.errors_for("safety.run_log_blank")


def test_payload_hidden_in_timestamp_column_flagged(mutable_data):
    # timestamp_pt is column 0 and otherwise unconstrained — a payload there must
    # still be caught by the blank-template guard.
    def populate(t: str) -> str:
        lines = t.splitlines()
        parts = lines[1].split(",")
        parts[0] = "an embargoed working break string"  # timestamp_pt
        lines[1] = ",".join(parts)
        return "\n".join(lines) + "\n"

    mutable_data.edit("ipi_july_2026_run_log.csv", populate)
    assert mutable_data.errors_for("safety.run_log_blank")


def test_hazard_hunt_non_identity_cell_flagged(mutable_data):
    def populate(t: str) -> str:
        lines = t.splitlines()
        parts = lines[1].split(",")
        parts[4] = "model-alias"
        lines[1] = ",".join(parts)
        return "\n".join(lines) + "\n"

    mutable_data.edit("hazard_hunt_q3_run_log.csv", populate)
    findings = mutable_data.errors_for("safety.run_log_blank")
    assert any(f.location.startswith("hazard_hunt_q3_run_log.csv:") for f in findings)


def test_injected_openai_key_flagged(mutable_data):
    mutable_data.edit(
        "README.md",
        lambda t: t + "\napi_key = sk-abcdefghijklmnopqrstuvwxyz0123456789\n",
    )
    assert mutable_data.errors_for("safety.secrets")


def test_injected_openai_project_key_flagged(mutable_data):
    # Modern project key: hyphenated body that the old pattern missed.
    mutable_data.edit(
        "README.md",
        lambda t: t + "\nkey = sk-proj-" + "a1b2c3d4e5" * 3 + "\n",
    )
    assert mutable_data.errors_for("safety.secrets")


def test_injected_github_fine_grained_pat_flagged(mutable_data):
    mutable_data.edit(
        "README.md",
        lambda t: t + "\npat = github_pat_" + "A1b2" * 8 + "\n",
    )
    assert mutable_data.errors_for("safety.secrets")


def test_secret_in_stray_data_file_flagged(mutable_data):
    # A file outside the seven canonical names must still be scanned AND flagged
    # as an unexpected artifact — the blind-spot the redteam pass found.
    mutable_data.write(
        "scratch_notes.md",
        "working notes\nAKIAABCDEFGHIJKLMNOP\nembargoed break string here\n",
    )
    ids = mutable_data.check_ids()
    assert "safety.secrets" in ids
    assert "safety.unexpected_files" in ids


def test_populated_local_csv_not_scanned(mutable_data):
    # A git-ignored *.local.csv working file is intentionally out of scope: it
    # is neither scanned for secrets nor flagged as unexpected.
    mutable_data.write(
        "ipi_july_2026_run_log.local.csv",
        "note,secret\nx,AKIAABCDEFGHIJKLMNOP\n",
    )
    ids = mutable_data.check_ids()
    assert "safety.unexpected_files" not in ids
    assert not any(
        f.location.startswith("ipi_july_2026_run_log.local.csv")
        for f in mutable_data.report().findings
    )


def test_injected_github_token_flagged(mutable_data):
    mutable_data.edit(
        "CLAUDE_CODE_HANDOFF.md",
        lambda t: t + "\ntoken ghp_" + "a" * 40 + "\n",
    )
    assert mutable_data.errors_for("safety.secrets")


def test_injected_private_key_flagged(mutable_data):
    mutable_data.edit(
        "ACTIVE_CHALLENGE_PLAYBOOK.md",
        lambda t: t + "\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n",
    )
    assert mutable_data.errors_for("safety.secrets")


def test_stripped_embargo_notice_flagged(mutable_data):
    def strip(t: str) -> str:
        out = []
        for line in t.splitlines():
            low = line.lower()
            if "30-day" in low or "30 days" in low or "do not publish" in low or "do not share" in low:
                continue
            out.append(line)
        return "\n".join(out) + "\n"

    mutable_data.edit("ACTIVE_CHALLENGE_PLAYBOOK.md", strip)
    assert mutable_data.errors_for("safety.embargo_notice")


def test_stripped_hazard_hunt_embargo_notice_flagged(mutable_data):
    # The Hazard Hunt playbook is embargo-guarded the same way as the IPI one.
    def strip(t: str) -> str:
        out = []
        for line in t.splitlines():
            low = line.lower()
            if "30-day" in low or "30 days" in low or "do not publish" in low or "forbids sharing" in low:
                continue
            out.append(line)
        return "\n".join(out) + "\n"

    mutable_data.edit("HAZARD_HUNT_PLAYBOOK.md", strip)
    findings = mutable_data.errors_for("safety.embargo_notice")
    assert any(f.location.startswith("HAZARD_HUNT_PLAYBOOK.md") for f in findings)


def test_hazard_hunt_embargo_notice_cannot_be_gamed(mutable_data):
    # Remove the real notice but leave benign lines that mention "30 days" and
    # "publish" separately. The three-group one-line requirement must still fire.
    def game(t: str) -> str:
        out = []
        for line in t.splitlines():
            low = line.lower()
            if ("30-day" in low or "30 days" in low) and (
                "publish" in low or "share" in low or "shar" in low
            ):
                continue
            out.append(line)
        out.append("The competition runs for about 30 days in total.")
        out.append("You may publish general methodology notes at any time.")
        return "\n".join(out) + "\n"

    mutable_data.edit("HAZARD_HUNT_PLAYBOOK.md", game)
    assert mutable_data.errors_for("safety.embargo_notice")


def test_embargo_notice_cannot_be_gamed(mutable_data):
    # Remove the real notice but leave an unrelated benign line that happens to
    # mention "30 days" and "publish" — separately. The strengthened check
    # requires embargo + action + subject on ONE line, so it must still fire.
    def game(t: str) -> str:
        out = []
        for line in t.splitlines():
            low = line.lower()
            if ("30-day" in low or "30 days" in low) and (
                "publish" in low or "share" in low or "shar" in low
            ):
                continue  # delete the real notice line(s)
            out.append(line)
        out.append("The competition runs for about 30 days in total.")
        out.append("You may publish general methodology notes at any time.")
        return "\n".join(out) + "\n"

    mutable_data.edit("ACTIVE_CHALLENGE_PLAYBOOK.md", game)
    assert mutable_data.errors_for("safety.embargo_notice")


def test_gitignore_rule_removal_flagged(mutable_data, parent_gitignore):
    parent_gitignore.write_text("# emptied\n", encoding="utf-8")
    assert mutable_data.errors_for("safety.gitignore")


def test_stray_email_warns(mutable_data):
    mutable_data.edit(
        "public_writeups_walkthroughs.csv",
        lambda t: t + "\n99,Leak,https://example.com,person@personal.example,2026,note,X,direct,public,\n",
    )
    warnings = [f for f in mutable_data.report().warnings if f.check == "safety.pii"]
    assert warnings


def test_allowlisted_reporting_email_not_flagged(dataset):
    # arena@grayswan.ai appears in the docs and must NOT be flagged.
    from redteam.datacheck.checks import check_safety_pii
    from redteam.core.findings import Report

    r = Report()
    check_safety_pii(dataset, r)
    assert not r.findings


def test_probe_id_word_boundary_not_flagged(mutable_data):
    # "task-details-..." contains "sk-" mid-word; the word-bounded openai_key
    # pattern must not read ordinary identifiers as OpenAI keys.
    mutable_data.edit(
        "README.md",
        lambda t: t + "\nid = task-details-fentanyl-synthesis-drip-screenplay\n",
    )
    assert not mutable_data.errors_for("safety.secrets")
