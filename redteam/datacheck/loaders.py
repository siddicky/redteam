"""Loading of the research data files.

Everything is read through :func:`load_dataset`, which returns a
:class:`Dataset` bundling the parsed CSV tables and the Markdown documents.
Parsing uses only the standard library so the core validator has no
third-party dependencies.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

# Repo layout: <project>/redteam/datacheck/loaders.py -> <project>/data
PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent.parent
DEFAULT_DATA_DIR = PROJECT_DIR / "data"

CSV_FILES = (
    "arena_challenges.csv",
    "proving_ground_waves.csv",
    "public_writeups_walkthroughs.csv",
    "ipi_july_2026_run_log.csv",
    "hazard_hunt_q3_run_log.csv",
)

DOC_FILES = (
    "README.md",
    "ACTIVE_CHALLENGE_PLAYBOOK.md",
    "HAZARD_HUNT_PLAYBOOK.md",
    "CLAUDE_CODE_HANDOFF.md",
    # Hierarchical agent documentation, generated per directory. A stable
    # named doc file, not a research artifact and not scratch — the
    # unexpected-files check still flags everything else.
    "AGENTS.md",
)

# The complete set of files expected to live in the data directory. Anything
# else committed there is flagged by the safety layer as an unexpected artifact.
EXPECTED_DATA_FILES = frozenset(CSV_FILES) | frozenset(DOC_FILES)

# Private working logs are git-ignored and deliberately not scanned/expected.
IGNORED_GLOBS = ("*.local.csv",)


class DataLoadError(Exception):
    """Raised only for unrecoverable load problems (missing dir / unreadable
    file). Row-level issues are reported as findings, not exceptions."""


@dataclass
class Table:
    """A parsed CSV file.

    ``header`` is the raw first row. ``rows`` are dict views keyed by header.
    ``raw_rows`` preserves the exact field lists (used to detect ragged rows
    and trailing/leading whitespace that a dict view would hide)."""

    name: str
    path: Path
    header: list[str]
    rows: list[dict[str, str]]
    raw_rows: list[list[str]]

    @property
    def row_count(self) -> int:
        return len(self.rows)

    def column(self, name: str) -> list[str]:
        return [r.get(name, "") for r in self.rows]

    def enumerate_rows(self, start: int = 2):
        """Yield ``(line_number, row)`` where ``line_number`` is the 1-based
        line in the file (row 1 is the header, so data starts at 2)."""
        for offset, row in enumerate(self.rows):
            yield start + offset, row


@dataclass
class Dataset:
    data_dir: Path
    tables: dict[str, Table] = field(default_factory=dict)
    docs: dict[str, str] = field(default_factory=dict)
    # Every file actually present under data_dir (relative POSIX paths), so the
    # safety layer can scan by directory walk rather than a fixed allowlist.
    present_files: list[str] = field(default_factory=list)

    def table(self, name: str) -> Table:
        if name not in self.tables:
            raise KeyError(f"table not loaded: {name}")
        return self.tables[name]

    def doc(self, name: str) -> str:
        if name not in self.docs:
            raise KeyError(f"doc not loaded: {name}")
        return self.docs[name]

    def is_ignored(self, relpath: str) -> bool:
        name = relpath.split("/")[-1]
        return any(fnmatch(name, pat) for pat in IGNORED_GLOBS)

    def scannable_files(self) -> list[str]:
        """Committed, non-ignored files under data_dir, excluding dotfiles and
        caches. These are the files the safety scanners read."""
        out = []
        for rel in self.present_files:
            parts = rel.split("/")
            if any(p.startswith(".") or p == "__pycache__" for p in parts):
                continue
            if self.is_ignored(rel):
                continue
            out.append(rel)
        return out

    def read_file(self, relpath: str) -> str:
        return (self.data_dir / relpath).read_text(encoding="utf-8", errors="ignore")


def _read_csv(path: Path, name: str) -> Table:
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        raw = list(reader)
    if not raw:
        return Table(name=name, path=path, header=[], rows=[], raw_rows=[])
    header = raw[0]
    raw_rows = raw[1:]
    rows: list[dict[str, str]] = []
    for fields in raw_rows:
        # zip stops at the shorter sequence; pad so short rows still map every
        # declared column (surfaced separately by the ragged-row check).
        padded = list(fields) + [""] * (len(header) - len(fields))
        rows.append(dict(zip(header, padded)))
    return Table(name=name, path=path, header=header, rows=rows, raw_rows=raw_rows)


def default_data_dir() -> Path:
    """Resolve the default data directory. Prefer the package-relative
    ``data/`` (in-place / editable use); fall back to ``./data`` so an installed
    console script still works when run from the project directory."""
    if DEFAULT_DATA_DIR.is_dir():
        return DEFAULT_DATA_DIR
    return Path.cwd() / "data"


def load_dataset(data_dir: str | Path | None = None) -> Dataset:
    """Load all CSVs and docs from ``data_dir`` (default: the project's
    ``data/`` directory)."""
    directory = Path(data_dir) if data_dir is not None else default_data_dir()
    directory = directory.resolve()
    if not directory.is_dir():
        raise DataLoadError(f"data directory not found: {directory}")

    ds = Dataset(data_dir=directory)
    ds.present_files = sorted(
        p.relative_to(directory).as_posix()
        for p in directory.rglob("*")
        if p.is_file()
    )
    for fname in CSV_FILES:
        path = directory / fname
        if not path.is_file():
            raise DataLoadError(f"required data file missing: {path}")
        ds.tables[fname] = _read_csv(path, fname)
    for fname in DOC_FILES:
        path = directory / fname
        if path.is_file():
            ds.docs[fname] = path.read_text(encoding="utf-8")
    return ds
