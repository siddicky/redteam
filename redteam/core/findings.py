"""Finding and Report primitives shared by every check.

The validation framework never raises on data problems: every issue becomes a
:class:`Finding` collected in a :class:`Report`. This keeps a single bad row
from hiding the rest of the results and lets the same logic drive both the CLI
and the pytest layer.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Ordered severities. ``ERROR`` fails the run; ``WARNING`` fails only
    under ``--strict``; ``INFO`` is never a failure."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """A single validation result.

    ``check`` is the stable id of the check that produced it (e.g.
    ``arena_challenges.row_count``). ``location`` points at the offending
    artifact, ideally ``file.csv:row`` so a human can jump straight to it.
    """

    check: str
    severity: Severity
    message: str
    location: str = ""

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": self.severity.value,
            "message": self.message,
            "location": self.location,
        }

    def format_line(self) -> str:
        where = f" [{self.location}]" if self.location else ""
        return f"{self.severity.value.upper():7} {self.check}{where}: {self.message}"


@dataclass
class Report:
    """Accumulates findings and answers the pass/fail question."""

    findings: list[Finding] = field(default_factory=list)

    def add(
        self,
        check: str,
        severity: Severity,
        message: str,
        location: str = "",
    ) -> None:
        self.findings.append(Finding(check, severity, message, location))

    def error(self, check: str, message: str, location: str = "") -> None:
        self.add(check, Severity.ERROR, message, location)

    def warning(self, check: str, message: str, location: str = "") -> None:
        self.add(check, Severity.WARNING, message, location)

    def info(self, check: str, message: str, location: str = "") -> None:
        self.add(check, Severity.INFO, message, location)

    def extend(self, other: "Report | list[Finding]") -> None:
        if isinstance(other, Report):
            self.findings.extend(other.findings)
        else:
            self.findings.extend(other)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.WARNING]

    @property
    def infos(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.INFO]

    def ok(self, strict: bool = False) -> bool:
        """True when the run passes. Any error fails; warnings fail only when
        ``strict`` is set."""
        if self.errors:
            return False
        if strict and self.warnings:
            return False
        return True

    def to_dict(self, strict: bool = False) -> dict:
        return {
            "ok": self.ok(strict=strict),
            "strict": strict,
            "counts": {
                "error": len(self.errors),
                "warning": len(self.warnings),
                "info": len(self.infos),
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, strict: bool = False) -> str:
        return json.dumps(self.to_dict(strict=strict), indent=2, sort_keys=False)

    def to_text(self, strict: bool = False, show_info: bool = True) -> str:
        lines: list[str] = []
        shown = [
            f
            for f in self.findings
            if show_info or f.severity is not Severity.INFO
        ]
        for f in shown:
            lines.append(f.format_line())
        status = "PASS" if self.ok(strict=strict) else "FAIL"
        summary = (
            f"{status}: {len(self.errors)} error(s), "
            f"{len(self.warnings)} warning(s), {len(self.infos)} info"
            + (" [strict]" if strict else "")
        )
        if lines:
            lines.append("")
        lines.append(summary)
        return "\n".join(lines)
