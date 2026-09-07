"""Detectors — how a response is judged.

Importing this package registers every built-in detector in :data:`DETECTORS`.
Read :mod:`redteam.detectors.base` for the three rules the detector layer follows;
they are the reason a report from this framework can be handed to an engineer.
"""

from __future__ import annotations

from typing import Any, Sequence

from ..core.errors import ConfigError
from .base import DETECTORS, DetectionContext, Detector, run_detectors

# Import for side effects: each module registers its detectors.
from . import builtin as _builtin  # noqa: F401
from .judge import judge_endpoints


def build_detector(detector_id: str, **options: Any) -> Detector:
    """Instantiate one detector by id."""
    try:
        return DETECTORS.create(detector_id, **options)
    except TypeError as exc:
        raise ConfigError(f"detector {detector_id!r}: {exc}") from None


def build_detectors(
    ids: Sequence[str],
    *,
    options: dict[str, dict[str, Any]] | None = None,
    cache: dict[str, Detector] | None = None,
) -> list[Detector]:
    """Instantiate several detectors, reusing instances via ``cache``.

    Caching matters for ``judge.llm``: without it every payload would construct a
    fresh judge target, and a run would open one connection per attempt.
    """
    per_detector = options or {}
    store = cache if cache is not None else {}
    built: list[Detector] = []
    for detector_id in ids:
        if detector_id not in store:
            store[detector_id] = build_detector(
                detector_id, **per_detector.get(detector_id, {})
            )
        built.append(store[detector_id])
    return built


def close_detectors(detectors: Sequence[Detector]) -> None:
    """Release any resources detectors hold (judge targets, mainly)."""
    for detector in detectors:
        closer = getattr(detector, "close", None)
        if callable(closer):
            closer()


__all__ = [
    "DETECTORS",
    "DetectionContext",
    "Detector",
    "build_detector",
    "build_detectors",
    "close_detectors",
    "judge_endpoints",
    "run_detectors",
]
