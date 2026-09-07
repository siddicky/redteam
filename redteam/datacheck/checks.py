"""Concrete checks: per-file invariants, cross-file consistency, and safety.

Each ``check_*`` function takes a loaded :class:`Dataset` and a :class:`Report`
and appends findings. They are registered in :data:`ALL_CHECKS` and run by
:func:`run_all`. The safety checks turn the handoff's "data-handling rule" into
automated gates so embargoed payloads or secrets cannot be committed silently.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict

from ..core.findings import Report
from ..core.redact import DEFAULT_EMAIL_ALLOWLIST, EMAIL_RE, SECRET_PATTERNS
from . import schema as S
from .loaders import Dataset, EXPECTED_DATA_FILES
from .validators import validate_schema, validate_sequential_int


def _to_int(value: str) -> int | None:
    value = value.strip()
    try:
        return int(value)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Per-file checks
# --------------------------------------------------------------------------- #
def check_arena_challenges(ds: Dataset, report: Report) -> None:
    table = ds.table("arena_challenges.csv")
    validate_schema(table, S.ARENA_CHALLENGES_SCHEMA, report)
    validate_sequential_int(table, S.ARENA_CHALLENGES_SCHEMA, "catalog_order", report)

    statuses = Counter(v.strip() for v in table.column("status_2026_09_03"))
    completed = sum(statuses[s] for s in S.COMPLETED_STATUSES)
    ongoing = sum(statuses[s] for s in S.ONGOING_STATUSES)

    if table.row_count == S.EXPECTED_CHALLENGE_COUNT and completed != S.EXPECTED_COMPLETED:
        report.error(
            "arena_challenges.completed_count",
            f"expected {S.EXPECTED_COMPLETED} completed challenges "
            f"(completed+completed_closed), found {completed}",
            location="arena_challenges.csv",
        )
    if table.row_count == S.EXPECTED_CHALLENGE_COUNT and ongoing != S.EXPECTED_ONGOING:
        report.error(
            "arena_challenges.ongoing_count",
            f"expected {S.EXPECTED_ONGOING} ongoing/practice challenges, found {ongoing}",
            location="arena_challenges.csv",
        )

    slugs = {v.strip() for v in table.column("slug")}
    missing = S.ONGOING_SLUGS - slugs
    if missing:
        report.error(
            "arena_challenges.ongoing_slugs",
            f"expected ongoing challenge slugs missing: {sorted(missing)}",
            location="arena_challenges.csv",
        )
    # Every declared ongoing slug must actually carry an ongoing-family status.
    for line_no, row in table.enumerate_rows():
        if row.get("slug", "").strip() in S.ONGOING_SLUGS:
            status = row.get("status_2026_09_03", "").strip()
            if status not in S.ONGOING_STATUSES:
                report.error(
                    "arena_challenges.ongoing_status_mismatch",
                    f"{row.get('slug')!r} is expected ongoing but status={status!r}",
                    location=f"arena_challenges.csv:{line_no}",
                )


def check_proving_ground(ds: Dataset, report: Report) -> None:
    table = ds.table("proving_ground_waves.csv")
    validate_schema(table, S.PROVING_GROUND_SCHEMA, report)

    waves_seen: set[int] = set()
    by_wave: dict[int, set[str]] = defaultdict(set)
    gap_waves: set[int] = set()

    for line_no, row in table.enumerate_rows():
        loc = f"proving_ground_waves.csv:{line_no}"
        wave = _to_int(row.get("wave", ""))
        category = row.get("category", "").strip()
        slug = row.get("behavior_slug", "").strip()
        visibility = row.get("live_visibility", "").strip()

        if wave is None:
            continue  # already reported by the pattern check
        if not (1 <= wave <= S.PROVING_GROUND_MAX_WAVE):
            report.error(
                "proving_ground.wave_range",
                f"wave {wave} outside 1..{S.PROVING_GROUND_MAX_WAVE}",
                location=loc,
            )
        waves_seen.add(wave)

        is_gap = visibility == "not_recovered"
        if is_gap:
            gap_waves.add(wave)
            if category != S.GAP_CATEGORY:
                report.error(
                    "proving_ground.gap_shape",
                    f"not_recovered row must use category {S.GAP_CATEGORY!r}, got {category!r}",
                    location=loc,
                )
            if slug != "":
                report.error(
                    "proving_ground.gap_shape",
                    f"not_recovered row must have empty behavior_slug, got {slug!r}",
                    location=loc,
                )
        else:
            if category == S.GAP_CATEGORY:
                report.error(
                    "proving_ground.gap_shape",
                    f"category {S.GAP_CATEGORY!r} only valid on not_recovered rows",
                    location=loc,
                )
            elif category in S.PROVING_GROUND_CATEGORIES:
                by_wave[wave].add(category)
            if slug == "":
                report.error(
                    "proving_ground.missing_slug",
                    "published behavior row has empty behavior_slug",
                    location=loc,
                )
            # Archived rows should only be the two archive-recovered waves.
            if visibility == "archived" and wave not in S.ARCHIVED_WAVES:
                report.warning(
                    "proving_ground.archived_wave",
                    f"wave {wave} marked archived; expected only {sorted(S.ARCHIVED_WAVES)}",
                    location=loc,
                )

    # Gap set must be exactly the unrecovered waves.
    if gap_waves != set(S.UNRECOVERED_WAVES):
        report.error(
            "proving_ground.unrecovered_waves",
            f"not_recovered waves {sorted(gap_waves)} != expected {sorted(S.UNRECOVERED_WAVES)}",
            location="proving_ground_waves.csv",
        )

    # Every published wave must expose all four behavior categories.
    for wave in sorted(waves_seen - set(S.UNRECOVERED_WAVES)):
        missing = S.PROVING_GROUND_CATEGORIES - by_wave.get(wave, set())
        if missing:
            report.error(
                "proving_ground.wave_categories",
                f"wave {wave} missing categories {sorted(missing)}",
                location="proving_ground_waves.csv",
            )

    # Full 1..26 coverage (published waves + gap markers).
    expected_waves = set(range(1, S.PROVING_GROUND_MAX_WAVE + 1))
    if waves_seen != expected_waves:
        report.error(
            "proving_ground.wave_coverage",
            f"waves present {sorted(waves_seen)} != 1..{S.PROVING_GROUND_MAX_WAVE}",
            location="proving_ground_waves.csv",
        )

    # Count published waves from OBSERVED content: a wave counts only if it
    # actually contributed at least one valid (non-gap) category row. Deriving
    # this from the data (rather than the set difference of schema constants)
    # means removing a wave's published rows drops the count and trips the check.
    published = len(by_wave)
    if published != S.EXPECTED_PUBLISHED_WAVES:
        report.error(
            "proving_ground.published_wave_count",
            f"expected {S.EXPECTED_PUBLISHED_WAVES} published waves "
            f"(with at least one behavior row), found {published}",
            location="proving_ground_waves.csv",
        )


def check_public_writeups(ds: Dataset, report: Report) -> None:
    table = ds.table("public_writeups_walkthroughs.csv")
    validate_schema(table, S.PUBLIC_WRITEUPS_SCHEMA, report)
    validate_sequential_int(table, S.PUBLIC_WRITEUPS_SCHEMA, "id", report)


def check_run_log(ds: Dataset, report: Report) -> None:
    table = ds.table("ipi_july_2026_run_log.csv")
    validate_schema(table, S.RUN_LOG_SCHEMA, report)

    if len(table.header) != len(S.RUN_LOG_SCHEMA.columns):
        report.error(
            "run_log.column_count",
            f"expected {len(S.RUN_LOG_SCHEMA.columns)} columns, found {len(table.header)}",
            location="ipi_july_2026_run_log.csv:1",
        )

    found = [
        (row.get("category", "").strip(), row.get("behavior", "").strip())
        for row in table.rows
    ]
    expected = list(S.RUN_LOG_BEHAVIORS)
    if sorted(found) != sorted(expected):
        missing = sorted(set(expected) - set(found))
        extra = sorted(set(found) - set(expected))
        report.error(
            "run_log.behavior_inventory",
            f"run-log behaviors do not match the canonical Wave-1 set; "
            f"missing={missing} extra={extra}",
            location="ipi_july_2026_run_log.csv",
        )

    counts = Counter(cat for cat, _ in found)
    for cat, expected_n in (("Coding Agent", 4), ("Computer / Browser Use", 3), ("Tool Use", 5)):
        if counts.get(cat, 0) != expected_n:
            report.error(
                "run_log.category_distribution",
                f"expected {expected_n} {cat!r} behaviors, found {counts.get(cat, 0)}",
                location="ipi_july_2026_run_log.csv",
            )


def check_hazard_hunt_run_log(ds: Dataset, report: Report) -> None:
    table = ds.table("hazard_hunt_q3_run_log.csv")
    validate_schema(table, S.HAZARD_HUNT_RUN_LOG_SCHEMA, report)

    if len(table.header) != len(S.HAZARD_HUNT_RUN_LOG_SCHEMA.columns):
        report.error(
            "hazard_hunt_run_log.column_count",
            f"expected {len(S.HAZARD_HUNT_RUN_LOG_SCHEMA.columns)} columns, found {len(table.header)}",
            location="hazard_hunt_q3_run_log.csv:1",
        )

    found = [
        (row.get("category", "").strip(), row.get("behavior_slug", "").strip())
        for row in table.rows
    ]
    expected = [(category, slug) for category, slug, _name in S.HAZARD_HUNT_BEHAVIORS]
    if found != expected:
        missing = sorted(set(expected) - set(found))
        extra = sorted(set(found) - set(expected))
        message = (
            "run-log behaviors do not match the canonical Hazard Hunt set and order; "
            + f"missing={missing} extra={extra}"
        )
        report.error(
            "hazard_hunt_run_log.behavior_inventory",
            message,
            location="hazard_hunt_q3_run_log.csv",
        )


# --------------------------------------------------------------------------- #
# Cross-file / doc-vs-data consistency checks
# --------------------------------------------------------------------------- #
_CHALLENGE_LINK_RE = re.compile(r"/arena/challenge/([a-z0-9-]+)")


def check_cross_readme_challenges(ds: Dataset, report: Report) -> None:
    if "README.md" not in ds.docs:
        report.warning("cross.readme_challenges", "README.md not present; skipped")
        return
    readme = ds.doc("README.md")
    table = ds.table("arena_challenges.csv")
    csv_slugs = {v.strip() for v in table.column("slug") if v.strip()}

    # README links a challenge's sub-page too (e.g. proving-ground/chat); the
    # regex stops at the next slash, so those collapse onto the base slug.
    readme_slugs = set(_CHALLENGE_LINK_RE.findall(readme))

    missing_in_readme = csv_slugs - readme_slugs
    if missing_in_readme:
        report.error(
            "cross.readme_challenges",
            f"catalogued challenges not linked in README: {sorted(missing_in_readme)}",
            location="README.md",
        )
    unknown_in_readme = readme_slugs - csv_slugs
    if unknown_in_readme:
        report.error(
            "cross.readme_challenges",
            f"README links challenge slugs absent from the catalog: {sorted(unknown_in_readme)}",
            location="README.md",
        )


def check_cross_playbook_runlog(ds: Dataset, report: Report) -> None:
    if "ACTIVE_CHALLENGE_PLAYBOOK.md" not in ds.docs:
        report.warning("cross.playbook_runlog", "playbook not present; skipped")
        return
    playbook = ds.doc("ACTIVE_CHALLENGE_PLAYBOOK.md")
    for category, behavior in S.RUN_LOG_BEHAVIORS:
        if behavior not in playbook:
            report.error(
                "cross.playbook_runlog",
                f"run-log behavior {behavior!r} ({category}) not documented in the playbook",
                location="ACTIVE_CHALLENGE_PLAYBOOK.md",
            )


def check_cross_wave_gaps(ds: Dataset, report: Report) -> None:
    if "README.md" not in ds.docs:
        return
    readme = ds.doc("README.md")
    # The README describes waves 7, 8, and 10 as unrecovered; assert each number
    # is mentioned so the prose cannot silently drift from the CSV markers.
    for wave in sorted(S.UNRECOVERED_WAVES):
        if not re.search(rf"\b{wave}\b", readme):
            report.warning(
                "cross.wave_gaps",
                f"README does not mention unrecovered wave {wave}",
                location="README.md",
            )


def check_handoff_filemap(ds: Dataset, report: Report) -> None:
    if "CLAUDE_CODE_HANDOFF.md" not in ds.docs:
        return
    handoff = ds.doc("CLAUDE_CODE_HANDOFF.md")
    referenced = set(re.findall(r"`([A-Za-z0-9_./-]+\.(?:csv|md))`", handoff))
    for fname in referenced:
        base = fname.split("/")[-1]
        if not (ds.data_dir / base).is_file():
            report.warning(
                "cross.handoff_filemap",
                f"handoff references {fname!r} but it is not in the data directory",
                location="CLAUDE_CODE_HANDOFF.md",
            )


def check_cross_wave_writeups(ds: Dataset, report: Report) -> None:
    """Every writeup URL cited on a proving-ground wave row must exist in the
    public writeups catalog (referential integrity between the two CSVs)."""
    waves = ds.table("proving_ground_waves.csv")
    writeups = ds.table("public_writeups_walkthroughs.csv")
    catalog_urls = {u.strip() for u in writeups.column("url") if u.strip()}
    for line_no, row in waves.enumerate_rows():
        url = row.get("public_writeup", "").strip()
        if url and url not in catalog_urls:
            report.error(
                "cross.wave_writeups",
                f"wave writeup URL {url!r} is not present in "
                f"public_writeups_walkthroughs.csv",
                location=f"proving_ground_waves.csv:{line_no}",
            )


def check_writeup_challenge_mapping(ds: Dataset, report: Report) -> None:
    """Soft check: every writeup's challenge_mapping should touch at least one
    known challenge title or a recognised Arena keyword. Non-fatal (INFO) since
    the mapping is curated free text."""
    table = ds.table("public_writeups_walkthroughs.csv")
    challenges = ds.table("arena_challenges.csv")
    title_tokens: set[str] = set()
    for title in challenges.column("title"):
        for tok in re.findall(r"[A-Za-z0-9]+", title.lower()):
            if len(tok) >= 4:
                title_tokens.add(tok)
    keywords = {"arena", "proving", "ground", "wave", "onboarding", "labyrinth"}
    vocabulary = title_tokens | keywords

    for line_no, row in table.enumerate_rows():
        mapping = row.get("challenge_mapping", "").lower()
        tokens = set(re.findall(r"[a-z0-9]+", mapping))
        if not tokens & vocabulary:
            report.info(
                "cross.writeup_mapping",
                f"challenge_mapping {row.get('challenge_mapping')!r} matches no known challenge token",
                location=f"public_writeups_walkthroughs.csv:{line_no}",
            )


# --------------------------------------------------------------------------- #
# Safety layer — enforces the handoff's data-handling rule
# --------------------------------------------------------------------------- #
# The credential and PII patterns are shared with the red-team framework's
# artifact redactor (:mod:`redteam.core.redact`). One source of truth means a
# pattern added to protect run transcripts also protects the committed research
# data, and neither copy can drift.
_COMPILED_SECRETS = [(name, re.compile(rx)) for name, rx in SECRET_PATTERNS]

# arena@grayswan.ai is the sanctioned vulnerability-reporting address.
_EMAIL_RE = EMAIL_RE
_EMAIL_ALLOWLIST = DEFAULT_EMAIL_ALLOWLIST


def _iter_source_texts(ds: Dataset):
    """Yield ``(relpath, text)`` for every committed, non-ignored file under the
    data directory — not just the seven canonical files. This closes the blind
    spot where a stray file (e.g. ``data/scratch.md``) could smuggle in secrets
    or embargoed payloads unscanned."""
    for rel in ds.scannable_files():
        yield rel, ds.read_file(rel)


def check_safety_unexpected_files(ds: Dataset, report: Report) -> None:
    """The data directory must contain only the known artifacts (plus git-ignored
    ``*.local.csv`` working files). Any other committed file is flagged — it is
    both an unexpected artifact and a potential smuggling vector for payloads."""
    for rel in ds.scannable_files():
        if rel not in EXPECTED_DATA_FILES:
            report.error(
                "safety.unexpected_files",
                f"unexpected file in data directory: {rel!r}. Only the known "
                f"research artifacts belong here; keep scratch/working files "
                f"out of the repo (or name them *.local.csv).",
                location=rel,
            )


def check_safety_secrets(ds: Dataset, report: Report) -> None:
    """No committed file may contain credentials or key material."""
    for name, text in _iter_source_texts(ds):
        for label, rx in _COMPILED_SECRETS:
            for m in rx.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                report.error(
                    "safety.secrets",
                    f"possible {label} detected; credentials must never be committed",
                    location=f"{name}:{line_no}",
                )


def check_safety_run_log_blank(ds: Dataset, report: Report) -> None:
    """The committed run log must stay a blank template: result/payload columns
    empty. This is the primary guard that keeps embargoed working strings and
    model-specific observations out of the repository."""
    for filename, blank_columns in (
        ("ipi_july_2026_run_log.csv", S.RUN_LOG_BLANK_COLUMNS),
        ("hazard_hunt_q3_run_log.csv", S.HAZARD_HUNT_BLANK_COLUMNS),
    ):
        table = ds.table(filename)
        result_cols = [column for column in blank_columns if column in table.header]
        for line_no, row in table.enumerate_rows():
            for column in result_cols:
                value = row.get(column, "").strip()
                if value != "":
                    report.error(
                        "safety.run_log_blank",
                        f"committed run log must stay blank; column {column!r} is populated "
                        f"({value!r}). Keep populated logs in a git-ignored *.local.csv file.",
                        location=f"{filename}:{line_no}",
                    )


def check_safety_embargo_notice(ds: Dataset, report: Report) -> None:
    """Each field-kit playbook must retain its embargo/no-publish warning so the
    safety guidance cannot be silently stripped."""
    # Require a single sentence/line that actually is the notice: it must tie the
    # embargo period to a no-publish/share action about working breaks/strings.
    # Testing all three groups on one line prevents the check from passing on
    # unrelated leftover phrases once the real notice is stripped.
    embargo_re = re.compile(r"30[\s-]?day|30\s+days", re.IGNORECASE)
    action_re = re.compile(r"do not (?:publish|share)|not share|forbids? shar", re.IGNORECASE)
    subject_re = re.compile(r"working|break|string|exploit|payload", re.IGNORECASE)
    for filename in ("ACTIVE_CHALLENGE_PLAYBOOK.md", "HAZARD_HUNT_PLAYBOOK.md"):
        if filename not in ds.docs:
            report.warning(
                "safety.embargo_notice",
                "playbook not present; skipped",
                location=filename,
            )
            continue
        text = ds.doc(filename)
        found = any(
            embargo_re.search(line) and action_re.search(line) and subject_re.search(line)
            for line in text.splitlines()
        )
        if not found:
            report.error(
                "safety.embargo_notice",
                "playbook is missing its working-break embargo notice (a single line "
                "must tie the 30-day embargo to a do-not-publish/share statement about "
                "working breaks/strings)",
                location=filename,
            )


def check_safety_pii(ds: Dataset, report: Report) -> None:
    """Flag email addresses other than the sanctioned reporting address."""
    for name, text in _iter_source_texts(ds):
        for m in _EMAIL_RE.finditer(text):
            email = m.group(0)
            if email.lower() in _EMAIL_ALLOWLIST:
                continue
            line_no = text.count("\n", 0, m.start()) + 1
            report.warning(
                "safety.pii",
                f"non-allowlisted email address {email!r}; confirm it is not personal data",
                location=f"{name}:{line_no}",
            )


def check_safety_gitignore(ds: Dataset, report: Report) -> None:
    """The blank-template workflow tells users to keep populated logs in a
    git-ignored ``*.local.csv`` file. Verify the ignore rule the safety design
    depends on is actually present next to the data directory."""
    gitignore = ds.data_dir.parent / ".gitignore"
    if not gitignore.is_file():
        report.warning(
            "safety.gitignore",
            "no .gitignore found next to the data directory; the private "
            "working-log workflow relies on a '*.local.csv' ignore rule",
            location=str(gitignore),
        )
        return
    text = gitignore.read_text(encoding="utf-8", errors="ignore")
    if "*.local.csv" not in text:
        report.error(
            "safety.gitignore",
            "'.gitignore' is missing the '*.local.csv' rule that keeps populated "
            "run logs (with embargoed payloads) out of the repository",
            location=str(gitignore),
        )


# --------------------------------------------------------------------------- #
# Registry / runner
# --------------------------------------------------------------------------- #
ALL_CHECKS = (
    check_arena_challenges,
    check_proving_ground,
    check_public_writeups,
    check_run_log,
    check_hazard_hunt_run_log,
    check_cross_readme_challenges,
    check_cross_playbook_runlog,
    check_cross_wave_gaps,
    check_cross_wave_writeups,
    check_handoff_filemap,
    check_writeup_challenge_mapping,
    check_safety_unexpected_files,
    check_safety_secrets,
    check_safety_run_log_blank,
    check_safety_embargo_notice,
    check_safety_pii,
    check_safety_gitignore,
)


def run_all(ds: Dataset) -> Report:
    report = Report()
    for check in ALL_CHECKS:
        check(ds, report)
    return report
