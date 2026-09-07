"""Reporter interface and the redaction boundary.

Every artifact this framework writes goes through a reporter, and every reporter
goes through :meth:`Reporter.render` — which is the single place where two
protections are applied:

* **Redaction.** Transcripts contain whatever the target echoed back, which on a
  real engagement can include credentials it was holding, customer records, or
  internal hostnames. All text is passed through :class:`~redteam.core.redact.Redactor`
  with the payload sentinels preserved, so evidence survives while secrets do not.
* **Payload suppression.** With ``include_payload_text=False`` artifacts carry
  payload *fingerprints* instead of payload text. That is the setting to use when a
  report leaves the engagement — attach the finding, not a working payload — and
  it is also how a corpus you are not licensed to redistribute stays out of a
  ticket.

The defaults deliberately differ by format. JSON is the machine artifact and keeps
full text so it can be replayed; Markdown and HTML are the human artifacts and
truncate excerpts, because a 40-page transcript dump is not a report anyone reads.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.redact import Redactor
from ..core.registry import Registry
from ..core.result import RunResult
from ..core.util import truncate

#: Registry of reporters, keyed by format name (``json``, ``markdown``, ``html``).
REPORTERS: Registry["Reporter"] = Registry("reporter")


@dataclass
class ReportOptions:
    """Presentation and disclosure settings for one artifact."""

    include_payload_text: bool = True
    include_raw_responses: bool = False
    redact: bool = True
    max_excerpt_chars: int = 600
    max_findings: int = 0  # 0 = all
    title: str = "AI red-team assessment"
    redactor: Redactor = field(default_factory=Redactor)

    def redactor_for(self, run: RunResult) -> Redactor:
        """A redactor that preserves every sentinel used in the run.

        Without this, a sentinel — a random token by design — can match a
        credential pattern and be redacted out of the very evidence that proves the
        finding.
        """
        if not self.redact:
            return Redactor(
                redact_secrets=False, redact_emails=False, redact_cards=False
            )
        sentinels = {
            a.payload.sentinel for a in run.attempts if a.payload.sentinel
        } | {
            str(a.payload.metadata.get("canary"))
            for a in run.attempts
            if a.payload.metadata.get("canary")
        }
        return self.redactor.with_preserved(*sentinels)


class Reporter(ABC):
    """Base class for output formats."""

    #: Set by :meth:`Registry.register`.
    id: str = ""
    #: One-line description for ``redteam list reporters``.
    description: str = ""
    #: File extension used when writing to a directory.
    extension: str = "txt"

    def __init__(self, **options: Any) -> None:
        self.options = options

    @abstractmethod
    def render(self, run: RunResult, options: ReportOptions) -> str:
        """Produce the artifact text."""

    def write(self, run: RunResult, options: ReportOptions, path: Path) -> Path:
        """Render and write, creating parent directories as needed."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(run, options), encoding="utf-8")
        return path

    def filename(self, run: RunResult) -> str:
        return f"{run.run_id}.{self.extension}"

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description
            or (self.__doc__ or "").strip().splitlines()[0],
            "extension": self.extension,
        }


# --------------------------------------------------------------------------- #
# Shared text helpers
# --------------------------------------------------------------------------- #
def clean(text: str, options: ReportOptions, redactor: Redactor, limit: int = 0) -> str:
    """Redact and optionally truncate a span of text for an artifact."""
    if not text:
        return ""
    cleaned = redactor.apply(text) if options.redact else text
    ceiling = limit or options.max_excerpt_chars
    return truncate(cleaned, ceiling) if ceiling else cleaned


def risk_badge(risk: str) -> str:
    """A short, plain-text severity marker.

    Text rather than colour: these artifacts land in CI logs, tickets, and pipes,
    none of which reliably render ANSI.
    """
    return {
        "critical": "[CRIT]",
        "high": "[HIGH]",
        "medium": "[MED ]",
        "low": "[LOW ]",
        "info": "[INFO]",
    }.get(risk, "[    ]")
