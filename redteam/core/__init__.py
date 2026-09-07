"""Core primitives: the data model, registries, config, and safety utilities.

Nothing in this package knows about a specific probe, target, or detector — the
extension points import *from* here, never the other way round.
"""

from __future__ import annotations

from .config import RunConfig, TargetConfig
from .errors import (
    AuthorizationError,
    BudgetExceeded,
    ConfigError,
    PolicyViolation,
    RedTeamError,
    RegistryError,
    TargetError,
)
from .findings import Finding, Report, Severity
from .ratelimit import Budget, RateLimiter, RetryPolicy, retry
from .redact import Redactor, redact
from .registry import Registry
from .result import (
    AttemptResult,
    Message,
    Outcome,
    Payload,
    Risk,
    RunResult,
    TargetResponse,
    ToolCall,
    Verdict,
    aggregate_verdicts,
    assistant,
    system,
    tool_result,
    user,
)
from .sentinel import SentinelFactory

__all__ = [
    "AttemptResult",
    "AuthorizationError",
    "Budget",
    "BudgetExceeded",
    "ConfigError",
    "Finding",
    "Message",
    "Outcome",
    "Payload",
    "PolicyViolation",
    "RateLimiter",
    "RedTeamError",
    "Redactor",
    "Registry",
    "RegistryError",
    "Report",
    "RetryPolicy",
    "Risk",
    "RunConfig",
    "RunResult",
    "SentinelFactory",
    "Severity",
    "TargetConfig",
    "TargetError",
    "TargetResponse",
    "ToolCall",
    "Verdict",
    "aggregate_verdicts",
    "assistant",
    "redact",
    "retry",
    "system",
    "tool_result",
    "user",
]
