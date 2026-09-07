"""Exception hierarchy.

The framework distinguishes three failure classes, and the CLI maps them to
distinct exit codes:

* :class:`ConfigError` / :class:`AuthorizationError` — the operator asked for
  something invalid or unauthorized. Nothing was sent. Exit code 2.
* :class:`TargetError` — a system under test misbehaved (transport failure, bad
  response shape). Recorded as an errored attempt, never fatal to the run.
* :class:`RedTeamError` — the base, for anything else.

Attack findings are *not* exceptions. A guardrail bypass is a normal, expected
result and is recorded as an :class:`~redteam.core.result.AttemptResult`.
"""

from __future__ import annotations


class RedTeamError(Exception):
    """Base class for every framework error."""


class ConfigError(RedTeamError):
    """Malformed or contradictory configuration."""


class AuthorizationError(RedTeamError):
    """The requested target is not covered by a valid authorization record.

    Raised *before* any request is issued. This is the framework's primary
    safety interlock and is never downgraded to a warning.
    """


class PolicyViolation(AuthorizationError):
    """The target is on the non-overridable denylist.

    Distinct from :class:`AuthorizationError` because it cannot be resolved by
    editing an authorization file — the platform's own rules of engagement
    forbid automated interaction.
    """


class TargetError(RedTeamError):
    """A system under test failed to produce a usable response."""


class BudgetExceeded(RedTeamError):
    """The run hit its authorized attempt budget."""


class RegistryError(RedTeamError):
    """Unknown or duplicate plugin id."""
