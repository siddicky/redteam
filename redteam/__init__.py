"""redteam — an automated red-teaming framework for LLM and agent deployments.

Point it at a system you are authorized to test, and it fires a corpus of attack
techniques at it, decides for each attempt whether the guardrail held, and produces
a report that names the rule that broke and how to fix it.

Six extension points, each a registry you can add to without touching the core:

======================  ==========================================================
:mod:`~redteam.targets`       the system under test (HTTP, subprocess, offline mock)
:mod:`~redteam.probes`        attack techniques, grouped into families
:mod:`~redteam.transforms`    payload mutations swept across the corpus
:mod:`~redteam.detectors`     the verdict on each response
:mod:`~redteam.orchestrators` run strategies (sweep, crescendo, adaptive)
:mod:`~redteam.reporting`     artifacts (console, JSON, Markdown, HTML, SARIF)
======================  ==========================================================

Two things make it usable on a real engagement rather than as a demo:

**The authorization gate.** :mod:`redteam.policy` requires a signed-off record
naming the systems in scope, with an attempt ceiling and a rate ceiling, before any
request is sent. Default deny, with an append-only denylist for platforms whose own
rules forbid automated interaction.

**Inert objectives.** Probes measure guardrail integrity using random sentinels
rather than harmful content, so a bypass is provable and this repository ships no
attack payloads. Bring your own corpus for harm-category evaluation via
``corpus.custom``.

Quick start, no credentials needed::

    python -m redteam run --config examples/offline-demo.config.json

Library use::

    from redteam import Authorization, RunConfig, execute_run, prepare_run

    config = RunConfig.load("redteam.config.json")
    authorization = Authorization.load("authorization.json")
    orchestrator, plan, ctx = prepare_run(config, authorization)
    result = execute_run(orchestrator, plan, ctx)
    print(result.ok(fail_on=None), len(result.findings()))
"""

from __future__ import annotations

from .core.config import RunConfig, TargetConfig
from .core.errors import (
    AuthorizationError,
    ConfigError,
    PolicyViolation,
    RedTeamError,
    TargetError,
)
from .core.result import (
    AttemptResult,
    Message,
    Outcome,
    Payload,
    Risk,
    RunResult,
    TargetResponse,
    ToolCall,
    Verdict,
)
from .detectors import DETECTORS, Detector
from .orchestrators import (
    ORCHESTRATORS,
    Orchestrator,
    RunPlan,
    execute_run,
    prepare_run,
)
from .policy import Authorization
from .probes import PROBES, Probe
from .reporting import REPORTERS, ReportOptions, render, write_reports
from .scoring import Metrics, summarize
from .targets import TARGETS, Target
from .transforms import TRANSFORMS, Transform

# isort: split
from . import dspy as _dspy_plugins  # noqa: F401

__version__ = "2.0.0"

__all__ = [
    "AttemptResult",
    "Authorization",
    "AuthorizationError",
    "ConfigError",
    "DETECTORS",
    "Detector",
    "Message",
    "Metrics",
    "ORCHESTRATORS",
    "Orchestrator",
    "Outcome",
    "PROBES",
    "Payload",
    "PolicyViolation",
    "Probe",
    "REPORTERS",
    "RedTeamError",
    "ReportOptions",
    "Risk",
    "RunConfig",
    "RunPlan",
    "RunResult",
    "TARGETS",
    "TRANSFORMS",
    "Target",
    "TargetConfig",
    "TargetError",
    "TargetResponse",
    "ToolCall",
    "Transform",
    "Verdict",
    "__version__",
    "execute_run",
    "prepare_run",
    "render",
    "summarize",
    "write_reports",
]
