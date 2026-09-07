"""Orchestrators — run strategies.

Importing this package registers ``sweep``, ``crescendo``, and ``adaptive`` in
:data:`ORCHESTRATORS`. See :mod:`redteam.orchestrators.base` for the plan/execute
split and where the authorization ceilings are applied.
"""

from __future__ import annotations

from .base import (
    ORCHESTRATORS,
    Orchestrator,
    PlannedAttempt,
    RunContext,
    RunPlan,
    execute_run,
    prepare_run,
)

# Import for side effects: registers the strategies.
from . import strategies as _strategies  # noqa: F401

__all__ = [
    "ORCHESTRATORS",
    "Orchestrator",
    "PlannedAttempt",
    "RunContext",
    "RunPlan",
    "execute_run",
    "prepare_run",
]
