"""Credential and PII redaction for anything the framework writes to disk.

Red-team artifacts are the highest-risk output this project produces: a run
transcript contains attack payloads, and — because the target is a real system —
it can contain whatever the target chose to echo back, including credentials it
was holding, customer data, or internal hostnames. Every reporter routes text
through :func:`redact` on the way out.

The pattern set is shared with :mod:`redteam.datacheck`, which uses it to keep
the same material out of the committed research data. One source of truth means
a pattern added for one purpose protects both.

Redaction is *not* a substitute for handling artifacts as sensitive. It is a
backstop against the common cases. ``docs/SAFETY.md`` covers the rest.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #
#: ``(label, regex)`` pairs for credential-shaped strings.
SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    ("aws_access_key", r"AKIA[0-9A-Z]{16}"),
    # Classic GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_) and fine-grained PATs.
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
    ("github_pat", r"github_pat_[A-Za-z0-9_]{22,}"),
    # OpenAI keys, including project/service-account keys (sk-proj-, sk-svcacct-)
    # whose bodies contain hyphens and underscores. Word-bounded so ordinary
    # words ending in "sk" ("task-details-…") cannot produce a mid-word match.
    ("openai_key", r"\bsk-[A-Za-z0-9_-]{20,}"),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    ("slack_token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("google_api_key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("azure_openai_key", r"(?i)api-key:\s*[A-Za-z0-9]{32}"),
    ("hf_token", r"hf_[A-Za-z0-9]{34,}"),
    ("private_key_block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("bearer_token", r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._\-]{20,}"),
    ("jwt", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
)

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

#: Long digit runs that look like payment cards (Luhn-checked before flagging).
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

_COMPILED_SECRETS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (label, re.compile(rx)) for label, rx in SECRET_PATTERNS
)

#: The vulnerability-reporting address carried in the research data. Allowlisted
#: so the safety scanners do not flag the very address they tell you to use.
DEFAULT_EMAIL_ALLOWLIST = frozenset({"arena@grayswan.ai"})


@dataclass(frozen=True)
class Match:
    """One redactable hit."""

    label: str
    value: str
    start: int
    line: int


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


# --------------------------------------------------------------------------- #
# Redactor
# --------------------------------------------------------------------------- #
@dataclass
class Redactor:
    """Configurable redaction pass.

    ``preserve`` holds strings that must survive verbatim — chiefly probe
    sentinels. A sentinel is a random-looking token, so a naive secret pattern
    could swallow it and destroy the evidence that a bypass occurred; preserving
    it explicitly keeps reports meaningful.
    """

    redact_secrets: bool = True
    redact_emails: bool = True
    redact_cards: bool = True
    email_allowlist: frozenset[str] = DEFAULT_EMAIL_ALLOWLIST
    extra_patterns: tuple[tuple[str, str], ...] = ()
    preserve: frozenset[str] = frozenset()
    _extra: tuple[tuple[str, re.Pattern[str]], ...] = field(
        default=(), init=False, repr=False
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_extra",
            tuple((label, re.compile(rx)) for label, rx in self.extra_patterns),
        )

    # -- scanning ---------------------------------------------------------- #
    def scan(self, text: str) -> list[Match]:
        """Every redactable hit in ``text``, in document order."""
        hits: list[Match] = []
        patterns = list(_COMPILED_SECRETS) + list(self._extra)
        if self.redact_secrets:
            for label, rx in patterns:
                for m in rx.finditer(text):
                    if self._is_preserved(m.group(0)):
                        continue
                    hits.append(Match(label, m.group(0), m.start(), _line_of(text, m.start())))
        if self.redact_emails:
            for m in EMAIL_RE.finditer(text):
                if m.group(0).lower() in self.email_allowlist:
                    continue
                hits.append(Match("email", m.group(0), m.start(), _line_of(text, m.start())))
        if self.redact_cards:
            for m in CARD_RE.finditer(text):
                digits = re.sub(r"[^0-9]", "", m.group(0))
                if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                    hits.append(
                        Match("payment_card", m.group(0), m.start(), _line_of(text, m.start()))
                    )
        hits.sort(key=lambda h: (h.start, h.label))
        return hits

    def _is_preserved(self, value: str) -> bool:
        return any(token and token in value for token in self.preserve)

    # -- rewriting --------------------------------------------------------- #
    def apply(self, text: str) -> str:
        """Return ``text`` with every hit replaced by ``[REDACTED:label]``."""
        if not text:
            return text
        hits = self.scan(text)
        if not hits:
            return text
        out: list[str] = []
        cursor = 0
        for hit in hits:
            if hit.start < cursor:  # overlapping match already covered
                continue
            out.append(text[cursor : hit.start])
            out.append(f"[REDACTED:{hit.label}]")
            cursor = hit.start + len(hit.value)
        out.append(text[cursor:])
        return "".join(out)

    def with_preserved(self, *tokens: str) -> "Redactor":
        """A copy that additionally preserves ``tokens`` verbatim."""
        extra = frozenset(t for t in tokens if t)
        return Redactor(
            redact_secrets=self.redact_secrets,
            redact_emails=self.redact_emails,
            redact_cards=self.redact_cards,
            email_allowlist=self.email_allowlist,
            extra_patterns=self.extra_patterns,
            preserve=self.preserve | extra,
        )


#: Shared default instance for callers that need no configuration.
DEFAULT_REDACTOR = Redactor()


def redact(text: str, redactor: Redactor | None = None) -> str:
    """Redact ``text`` with ``redactor`` (default: :data:`DEFAULT_REDACTOR`)."""
    return (redactor or DEFAULT_REDACTOR).apply(text)


def scan(text: str, redactor: Redactor | None = None) -> list[Match]:
    return (redactor or DEFAULT_REDACTOR).scan(text)


# --------------------------------------------------------------------------- #
# Excerpting for evidence
# --------------------------------------------------------------------------- #
def excerpt(text: str, needle: str = "", width: int = 160) -> str:
    """A short, single-line excerpt of ``text`` centred on ``needle``.

    Detector evidence must be short enough to skim in a report and long enough
    to justify the verdict. Newlines collapse to ``\\n`` so one finding stays one
    line in text output.
    """
    flat = text.replace("\r\n", "\n")
    if needle:
        index = flat.lower().find(needle.lower())
    else:
        index = -1
    if index < 0:
        window = flat[:width]
        ellipsis = "…" if len(flat) > width else ""
        return _flatten(window) + ellipsis
    half = max(width - len(needle), 0) // 2
    start = max(index - half, 0)
    end = min(index + len(needle) + half, len(flat))
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(flat) else ""
    return prefix + _flatten(flat[start:end]) + suffix


def _flatten(text: str) -> str:
    return text.replace("\n", "\\n").replace("\t", " ").strip()
