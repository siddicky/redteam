"""Rules of engagement, expressed as code.

:mod:`redteam.policy.authorization` holds the gate every target must pass before
a single request is sent. See its module docstring for the three rules it
enforces.
"""

from __future__ import annotations

from .authorization import (
    BUILTIN_DENYLIST,
    OFFLINE_SCHEMES,
    Authorization,
    Scope,
    is_offline_endpoint,
)

__all__ = [
    "BUILTIN_DENYLIST",
    "OFFLINE_SCHEMES",
    "Authorization",
    "Scope",
    "is_offline_endpoint",
]
