"""Reporting — artifacts for humans, machines, and CI.

Importing this package registers every format in :data:`REPORTERS`. See
:mod:`redteam.reporting.base` for the redaction boundary every artifact passes
through.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Sequence

from ..core.errors import ConfigError
from ..core.result import RunResult
from .base import REPORTERS, ReportOptions, Reporter

# Import for side effects: registers the formats.
from . import formats as _formats  # noqa: F401


def build_reporter(format_id: str, **options: Any) -> Reporter:
    try:
        return REPORTERS.create(format_id, **options)
    except TypeError as exc:
        raise ConfigError(f"reporter {format_id!r}: {exc}") from None


def render(run: RunResult, format_id: str, options: ReportOptions | None = None) -> str:
    """Render one run in one format."""
    return build_reporter(format_id).render(run, options or ReportOptions())


def write_reports(
    run: RunResult,
    formats: Sequence[str],
    output_dir: str | Path,
    options: ReportOptions | None = None,
) -> list[Path]:
    """Write one artifact per format into ``output_dir``.

    Every format is attempted even if one fails, and the failure is raised only
    after the rest are on disk: losing the JSON artifact because the HTML reporter
    hit an edge case would throw away the run.
    """
    opts = options or ReportOptions()
    directory = Path(output_dir)
    written: list[Path] = []
    errors: list[str] = []
    for format_id in formats:
        try:
            reporter = build_reporter(format_id)
            written.append(
                reporter.write(run, opts, directory / reporter.filename(run))
            )
        except Exception as exc:  # noqa: BLE001 - collected, raised below
            errors.append(f"{format_id}: {type(exc).__name__}: {exc}")
    if errors:
        raise ConfigError(
            "some reports failed to write (" + "; ".join(errors) + ")"
        )
    return written


__all__ = [
    "REPORTERS",
    "ReportOptions",
    "Reporter",
    "build_reporter",
    "render",
    "write_reports",
]
