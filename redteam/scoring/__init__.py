"""Scoring — metrics, findings triage, and run comparison.

See :mod:`redteam.scoring.metrics` for why attack success rate is computed the way
it is; the denominator choice is the difference between a number that means
something and one that flatters the target.
"""

from __future__ import annotations

from .metrics import (
    RISK_WEIGHTS,
    Metrics,
    Rate,
    compare,
    deduplicate_findings,
    resilience_score,
    summarize,
    summarize_attempts,
    top_findings,
)

__all__ = [
    "RISK_WEIGHTS",
    "Metrics",
    "Rate",
    "compare",
    "deduplicate_findings",
    "resilience_score",
    "summarize",
    "summarize_attempts",
    "top_findings",
]
