"""Target adapters — the systems under test.

Importing this package registers every built-in adapter in :data:`TARGETS`.
Add your own by importing :class:`Target` and decorating a subclass; see
``docs/EXTENDING.md``.
"""

from __future__ import annotations

from ..core.config import TargetConfig
from ..core.errors import ConfigError
from .base import TARGETS, SYSTEM_MODES, Target

# Import for side effects: each module registers its adapters.
from . import command as _command  # noqa: F401
from . import http as _http  # noqa: F401
from . import mock as _mock  # noqa: F401
from . import replay as _replay  # noqa: F401


def build_target(config: TargetConfig, *, timeout: float | None = None) -> Target:
    """Instantiate the adapter named by ``config``.

    Option errors are re-raised with the target's label attached — with a dozen
    targets in a config, "missing option 'model'" is not an actionable message.
    """
    options = dict(config.options)
    options.setdefault("label", config.id)
    if timeout is not None:
        options.setdefault("timeout", timeout)
    try:
        return TARGETS.create(config.plugin, **options)
    except ConfigError as exc:
        raise ConfigError(f"target {config.id!r}: {exc}") from None
    except TypeError as exc:
        raise ConfigError(
            f"target {config.id!r} ({config.plugin}): {exc}"
        ) from None


__all__ = ["SYSTEM_MODES", "TARGETS", "Target", "build_target"]
