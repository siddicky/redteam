"""The authorization gate — the framework's primary safety interlock.

An automated red-team harness differs from a data validator in one way that
matters: it sends adversarial traffic to a live system. Whether that is
legitimate security work or an attack depends entirely on whether the operator
was authorized to do it, and that fact lives outside the code. So the framework
requires it *in* the code.

Three rules, enforced here and not bypassable from a config file:

1. **Default deny.** A target is only reachable if its endpoint matches a
   pattern in an authorization record's ``scope.targets``. There is no
   "authorize everything" wildcard; the scope must enumerate what you may hit.
2. **Append-only denylist.** Operators can refuse additional hosts via
   ``scope.deny``. Built-in entries, if any, cannot be removed by a local file.
   The denylist is consulted before scope, so a denied host cannot be unlocked
   by also listing it in ``scope.targets``.
3. **Bounded and expiring.** Every record carries an attempt ceiling, a rate
   ceiling, and an expiry date. An expired record authorizes nothing.

Offline targets (``mock:``, ``replay:``) need no record: they generate no
traffic and involve no third party. :meth:`Authorization.offline` covers them so
that the test suite and the demo path do not train operators to wave the gate
away.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..core.errors import AuthorizationError, ConfigError, PolicyViolation

# --------------------------------------------------------------------------- #
# Non-overridable denylist
# --------------------------------------------------------------------------- #
#: Hosts this framework refuses to drive, with the reason. Operators append via
#: ``scope.deny``; entries here cannot be removed by a local authorization file.
BUILTIN_DENYLIST: tuple[tuple[str, str], ...] = ()

#: Scope patterns that are refused because they authorize everything.
_FORBIDDEN_SCOPE_PATTERNS = frozenset({"*", "**", "*:*", "*://*", "*://*/*", "http://*", "https://*"})

#: Offline endpoint schemes that require no authorization record.
OFFLINE_SCHEMES = ("mock:", "replay:", "static:")

MAX_ATTEMPT_CEILING = 100_000


def is_offline_endpoint(endpoint: str) -> bool:
    """True for endpoints that generate no outbound traffic."""
    return endpoint.startswith(OFFLINE_SCHEMES)


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Scope:
    """What an authorization record permits."""

    targets: tuple[str, ...] = ()
    max_attempts: int = 0
    max_requests_per_minute: float = 0.0
    max_concurrency: int = 0
    deny: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Any) -> "Scope":
        if not isinstance(data, dict):
            raise ConfigError("authorization 'scope' must be an object")
        patterns = data.get("targets")
        if not isinstance(patterns, list) or not patterns:
            raise ConfigError(
                "authorization scope.targets must be a non-empty list of endpoint "
                "patterns (e.g. [\"https://llm.staging.internal.example.com/*\"])"
            )
        cleaned: list[str] = []
        for pattern in patterns:
            if not isinstance(pattern, str) or not pattern.strip():
                raise ConfigError("authorization scope.targets entries must be strings")
            pattern = pattern.strip()
            if pattern in _FORBIDDEN_SCOPE_PATTERNS:
                raise ConfigError(
                    f"authorization scope.targets may not contain the catch-all "
                    f"pattern {pattern!r}. Enumerate the systems you are authorized "
                    f"to test — a blanket wildcard is not an authorization."
                )
            cleaned.append(pattern)

        max_attempts = int(data.get("max_attempts") or 0)
        if max_attempts <= 0:
            raise ConfigError(
                "authorization scope.max_attempts must be a positive integer — an "
                "authorization record has to state a ceiling"
            )
        if max_attempts > MAX_ATTEMPT_CEILING:
            raise ConfigError(
                f"authorization scope.max_attempts {max_attempts} exceeds the "
                f"framework ceiling of {MAX_ATTEMPT_CEILING}; split the engagement "
                f"into separate authorized runs"
            )
        rpm = float(data.get("max_requests_per_minute") or 0.0)
        if rpm <= 0:
            raise ConfigError(
                "authorization scope.max_requests_per_minute must be positive — "
                "unbounded request rates risk a denial-of-service on the target"
            )
        return cls(
            targets=tuple(cleaned),
            max_attempts=max_attempts,
            max_requests_per_minute=rpm,
            max_concurrency=int(data.get("max_concurrency") or 0),
            deny=tuple(str(d).strip() for d in (data.get("deny") or []) if str(d).strip()),
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "targets": list(self.targets),
            "max_attempts": self.max_attempts,
            "max_requests_per_minute": self.max_requests_per_minute,
        }
        if self.max_concurrency:
            out["max_concurrency"] = self.max_concurrency
        if self.deny:
            out["deny"] = list(self.deny)
        return out


# --------------------------------------------------------------------------- #
# Authorization
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Authorization:
    """A signed-off statement of what testing is permitted.

    This object is recorded verbatim (minus contact details) in every run
    artifact, so a report always carries the authority it was produced under.
    """

    engagement: str
    authorized_by: str
    scope: Scope
    reference: str = ""
    issued: str = ""
    expires: str = ""
    contacts: dict[str, str] = field(default_factory=dict)
    notes: str = ""
    acknowledged: bool = False
    arena_live_actions_acknowledged: bool = False
    source_path: str = ""
    offline_only: bool = False

    # -- loading ----------------------------------------------------------- #
    @classmethod
    def from_dict(cls, data: Any, *, source_path: str = "") -> "Authorization":
        if not isinstance(data, dict):
            raise ConfigError("authorization root must be an object")
        version = int(data.get("version") or 1)
        if version != 1:
            raise ConfigError(f"unsupported authorization version {version}; expected 1")

        for required in ("engagement", "authorized_by", "expires"):
            if not str(data.get(required) or "").strip():
                raise ConfigError(f"authorization is missing required field {required!r}")

        ack = data.get("acknowledgements") or {}
        if not isinstance(ack, dict):
            raise ConfigError("authorization 'acknowledgements' must be an object")
        missing = [
            key
            for key in ("authorized", "rules_of_engagement_reviewed")
            if ack.get(key) is not True
        ]
        if missing:
            raise ConfigError(
                "authorization acknowledgements must set "
                + ", ".join(f"{k}=true" for k in missing)
                + " — this is the operator's attestation that the engagement is "
                "authorized and the rules of engagement were read"
            )

        expires = str(data["expires"]).strip()
        _parse_date(expires, "expires")
        issued = str(data.get("issued") or "").strip()
        if issued:
            _parse_date(issued, "issued")

        return cls(
            engagement=str(data["engagement"]).strip(),
            authorized_by=str(data["authorized_by"]).strip(),
            scope=Scope.from_dict(data.get("scope")),
            reference=str(data.get("reference") or "").strip(),
            issued=issued,
            expires=expires,
            contacts={str(k): str(v) for k, v in (data.get("contacts") or {}).items()},
            notes=str(data.get("notes") or "").strip(),
            acknowledged=True,
            arena_live_actions_acknowledged=ack.get("arena_live_actions") is True,
            source_path=source_path,
        )

    @classmethod
    def load(cls, path: str | Path) -> "Authorization":
        file = Path(path)
        if not file.is_file():
            raise ConfigError(
                f"authorization file not found: {file}. Run 'redteam init' to "
                f"scaffold one, then have it signed off before testing."
            )
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{file}: invalid JSON — {exc}") from None
        return cls.from_dict(data, source_path=str(file))

    @classmethod
    def offline(cls) -> "Authorization":
        """The implicit authorization for offline targets only.

        Covers ``mock:``/``replay:``/``static:`` endpoints, which reach no
        network and no third party. Any other endpoint under this record is
        refused with a message pointing at the real gate.
        """
        return cls(
            engagement="offline self-test (mock and replay targets only)",
            authorized_by="implicit — no external system is contacted",
            scope=Scope(
                targets=("mock:*", "replay:*", "static:*"),
                max_attempts=MAX_ATTEMPT_CEILING,
                max_requests_per_minute=float(MAX_ATTEMPT_CEILING),
            ),
            expires="9999-12-31",
            acknowledged=True,
            offline_only=True,
        )

    # -- validity ---------------------------------------------------------- #
    def expiry_date(self) -> date:
        return _parse_date(self.expires, "expires")

    def is_expired(self, today: date | None = None) -> bool:
        return self.expiry_date() < (today or date.today())

    def days_remaining(self, today: date | None = None) -> int:
        return (self.expiry_date() - (today or date.today())).days

    def require_valid(self, today: date | None = None) -> None:
        if self.is_expired(today):
            raise AuthorizationError(
                f"authorization expired on {self.expires} "
                f"({self.source_path or 'inline record'}). Renew the engagement "
                f"sign-off before testing again."
            )

    # -- the gate ---------------------------------------------------------- #
    def denylist(self) -> tuple[tuple[str, str], ...]:
        """Built-in denials plus any the operator appended. Append-only."""
        extra = tuple(
            (entry, "added by scope.deny in the authorization record")
            for entry in self.scope.deny
        )
        return BUILTIN_DENYLIST + extra

    def check_denylist(self, endpoint: str) -> None:
        """Raise :class:`PolicyViolation` if ``endpoint`` is denied.

        URL endpoints are matched on hostname (so a denied domain also covers
        its subdomains and every path on it). Non-URL endpoints — ``exec:``
        command lines, for instance — have no host to compare, so they fall back
        to a substring match on the whole endpoint.
        """
        host = _host_of(endpoint)
        lowered = endpoint.lower()
        for pattern, reason in self.denylist():
            pattern_l = pattern.lower()
            denied = (
                _host_matches(host, pattern_l) if host else pattern_l in lowered
            )
            if denied:
                raise PolicyViolation(f"target {endpoint!r} is denied: {reason}")

    def in_scope(self, endpoint: str) -> bool:
        return any(_endpoint_matches(endpoint, pattern) for pattern in self.scope.targets)

    def authorize(self, endpoint: str, *, today: date | None = None) -> None:
        """Permit ``endpoint`` or raise.

        Order matters: the denylist is consulted first, so a denied host cannot
        be reached by also listing it in scope.
        """
        self.require_valid(today)
        self.check_denylist(endpoint)
        if self.in_scope(endpoint):
            return
        if self.offline_only:
            raise AuthorizationError(
                f"target {endpoint!r} needs an authorization record. Only offline "
                f"targets (mock:, replay:, static:) run without one. Pass "
                f"--auth authorization.json once the engagement is signed off."
            )
        raise AuthorizationError(
            f"target {endpoint!r} is not in the authorized scope "
            f"({', '.join(self.scope.targets)}). Add it to scope.targets in "
            f"{self.source_path or 'the authorization record'} only if the "
            f"engagement actually covers it."
        )

    def effective_rate(self, requested: float) -> float:
        """The lower of the requested and authorized request rates."""
        if requested <= 0:
            return self.scope.max_requests_per_minute
        return min(requested, self.scope.max_requests_per_minute)

    def effective_attempts(self, requested: int) -> int:
        """The lower of the requested and authorized attempt ceilings."""
        if requested <= 0:
            return self.scope.max_attempts
        return min(requested, self.scope.max_attempts)

    def effective_concurrency(self, requested: int) -> int:
        if self.scope.max_concurrency <= 0:
            return max(1, requested)
        return max(1, min(requested, self.scope.max_concurrency))

    # -- the run record ---------------------------------------------------- #
    def record(self) -> dict:
        """Authorization provenance for a run artifact.

        Contact details are omitted: they are personal data and a run artifact
        travels widely.
        """
        return {
            "engagement": self.engagement,
            "authorized_by": self.authorized_by,
            "reference": self.reference,
            "issued": self.issued,
            "expires": self.expires,
            "offline_only": self.offline_only,
            "scope": self.scope.to_dict(),
            "source": self.source_path,
        }

    def summary(self) -> str:
        who = f" (ref {self.reference})" if self.reference else ""
        return (
            f"{self.engagement}{who}\n"
            f"  authorized by : {self.authorized_by}\n"
            f"  expires       : {self.expires} ({self.days_remaining()} day(s) left)\n"
            f"  scope         : {', '.join(self.scope.targets)}\n"
            f"  ceilings      : {self.scope.max_attempts} attempts, "
            f"{self.scope.max_requests_per_minute:g} req/min"
        )


# --------------------------------------------------------------------------- #
# Matching helpers
# --------------------------------------------------------------------------- #
def _parse_date(value: str, field_name: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ConfigError(
            f"authorization {field_name!r} must be an ISO date (YYYY-MM-DD), got {value!r}"
        ) from None


def _host_of(endpoint: str) -> str:
    """Hostname of an http(s) endpoint, or '' for non-URL endpoints."""
    if "://" not in endpoint:
        return ""
    try:
        return (urlsplit(endpoint).hostname or "").lower()
    except ValueError:
        return ""


def _host_matches(host: str, pattern: str) -> bool:
    """Host-or-subdomain match, so ``example.com`` covers ``app.example.com``."""
    pattern = pattern.strip().lstrip(".")
    if not pattern:
        return False
    if "*" in pattern:
        return fnmatch(host, pattern)
    return host == pattern or host.endswith("." + pattern)


def _endpoint_matches(endpoint: str, pattern: str) -> bool:
    """Scope matching.

    A glob on the whole endpoint string handles the common cases
    (``https://api.internal.example.com/*``, ``mock:*``, ``exec:./bin/agent``).
    A bare host pattern additionally matches any URL on that host, so operators
    do not have to guess path shapes; a pattern with a scheme is matched
    literally so ``http://`` in scope never silently authorizes ``https://``
    (or the reverse) on a different port.
    """
    endpoint_l = endpoint.strip()
    pattern = pattern.strip()
    if fnmatch(endpoint_l, pattern):
        return True
    if "://" not in pattern and ":" not in pattern.split("/", 1)[0]:
        host = _host_of(endpoint_l)
        if host and _host_matches(host, pattern):
            return True
    # Allow a scoped prefix without a trailing glob to cover its subpaths.
    if pattern.endswith("/") and endpoint_l.startswith(pattern):
        return True
    return False
