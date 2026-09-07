"""Probes — the attack technique library.

Importing this package registers every built-in probe in :data:`PROBES`. Selection
accepts exact ids (``indirect.document``), family prefixes (``indirect``), globs
(``*.tool_output``), and tags (``--tag owasp-llm01``).

The corpus is deliberately readable as data: templates and ladders live in module
constants rather than being generated, because the probe corpus is the part of a
red-team tool a reviewer needs to be able to audit in a diff.
"""

from __future__ import annotations

from typing import Any, Iterator, Sequence

from ..core.errors import ConfigError
from ..core.result import Payload
from .base import (
    DEFAULT_ORG,
    DEFAULT_SYSTEM_PROMPT,
    PROBES,
    Probe,
    ProbeContext,
    TemplateProbe,
    Variant,
)

# Import for side effects: each module registers its probes.
from . import agency as _agency  # noqa: F401
from . import corpus as _corpus  # noqa: F401
from . import direct as _direct  # noqa: F401
from . import exfiltration as _exfiltration  # noqa: F401
from . import framing as _framing  # noqa: F401
from . import indirect as _indirect  # noqa: F401
from . import intent as _intent  # noqa: F401
from . import leakage as _leakage  # noqa: F401
from . import mcp as _mcp  # noqa: F401
from . import multiturn as _multiturn  # noqa: F401
from . import output_handling as _output_handling  # noqa: F401


def build_probe(probe_id: str, **options: Any) -> Probe:
    """Instantiate one probe by id."""
    try:
        return PROBES.create(probe_id, **options)
    except TypeError as exc:
        raise ConfigError(f"probe {probe_id!r}: {exc}") from None


def select_probes(
    selectors: Sequence[str] | None = None,
    *,
    include_tags: Sequence[str] = (),
    exclude_tags: Sequence[str] = (),
    probe_options: dict[str, dict[str, Any]] | None = None,
) -> list[Probe]:
    """Resolve selectors and tag filters into instantiated probes.

    Tag filtering is applied after id resolution so ``--probe indirect --tag
    coding-agent`` narrows rather than widens. An explicit id that a tag filter
    then removes is not an error — it is the operator composing two filters — but
    an empty final set is, because a run with no probes would report a
    meaningless pass.
    """
    options = probe_options or {}
    ids = PROBES.resolve(list(selectors) if selectors else None)
    probes: list[Probe] = []
    for probe_id in ids:
        probe = build_probe(probe_id, **options.get(probe_id, {}))
        tags = set(probe.tags)
        if include_tags and not tags & set(include_tags):
            continue
        if exclude_tags and tags & set(exclude_tags):
            continue
        probes.append(probe)
    if not probes:
        raise ConfigError(
            "probe selection is empty. Selectors "
            f"{list(selectors or ['<all>'])} with include_tags={list(include_tags)} "
            f"exclude_tags={list(exclude_tags)} matched no probes."
        )
    return probes


def generate_payloads(probes: Sequence[Probe], ctx: ProbeContext) -> Iterator[tuple[Probe, Payload]]:
    """Yield ``(probe, payload)`` for every payload the probes produce."""
    for probe in probes:
        for payload in probe.payloads(ctx):
            yield probe, payload


__all__ = [
    "DEFAULT_ORG",
    "DEFAULT_SYSTEM_PROMPT",
    "PROBES",
    "Probe",
    "ProbeContext",
    "TemplateProbe",
    "Variant",
    "build_probe",
    "generate_payloads",
    "select_probes",
]
