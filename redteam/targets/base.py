"""The target interface: one adapter per kind of system under test.

A *target* is anything that takes a conversation and returns a response — a
hosted model API, an internal RAG service, an agent behind a CLI, or the offline
simulator. Probes and detectors know nothing about which one they are talking
to, so the same probe corpus runs against a raw model and against the
application wrapped around it. That distinction matters in practice: guardrails
usually live in the wrapper, and the wrapper is what ships.

Two responsibilities every adapter must honour:

* :attr:`Target.endpoint` — a stable string the authorization gate can match.
  It has to describe what will actually be contacted; an adapter that reported a
  friendly name here would defeat the gate.
* ``system_prompt_mode`` — how the target handles a ``system`` turn. Several
  probes work by planting an instruction (or a canary) in the system prompt, and
  a target that silently discards system messages would make those probes look
  like passes. Declaring the behaviour lets the orchestrator skip them instead.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, Sequence

from ..core.errors import ConfigError, TargetError
from ..core.registry import Registry
from ..core.result import Message, TargetResponse

#: Registry of target adapters, keyed by dotted plugin id.
TARGETS: Registry["Target"] = Registry("target")

#: How a target treats ``system`` turns.
SYSTEM_MODES = ("pass", "merge", "drop")


class Target(ABC):
    """Base class for systems under test."""

    #: Set by :meth:`Registry.register`.
    id: str = ""

    def __init__(
        self,
        *,
        label: str = "",
        system_prompt_mode: str = "pass",
        timeout: float = 60.0,
        max_output_chars: int = 20_000,
        **extra: Any,
    ) -> None:
        if system_prompt_mode not in SYSTEM_MODES:
            raise ConfigError(
                f"system_prompt_mode must be one of {SYSTEM_MODES}, got "
                f"{system_prompt_mode!r}"
            )
        self.label = label or self.id
        self.system_prompt_mode = system_prompt_mode
        self.timeout = float(timeout)
        self.max_output_chars = int(max_output_chars)
        if extra:
            raise ConfigError(
                f"target {self.id!r}: unknown option(s) {', '.join(sorted(extra))}"
            )

    # -- identity ---------------------------------------------------------- #
    @property
    @abstractmethod
    def endpoint(self) -> str:
        """What will be contacted, for the authorization gate to match.

        Must be the real destination — a URL for HTTP adapters, ``exec:<argv>``
        for a subprocess, ``mock:<profile>`` for the simulator.
        """

    @property
    def supports_tools(self) -> bool:
        """Whether the adapter can offer tool schemas to the target."""
        return False

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.label,
            "plugin": self.id,
            "endpoint": self.endpoint,
            "system_prompt_mode": self.system_prompt_mode,
            "supports_tools": self.supports_tools,
        }

    # -- the call ---------------------------------------------------------- #
    @abstractmethod
    def _send(
        self, messages: Sequence[Message], tools: Sequence[dict[str, Any]]
    ) -> TargetResponse:
        """Adapter-specific send. Raise :class:`TargetError` on transport faults."""

    def send(
        self,
        messages: Sequence[Message],
        *,
        tools: Sequence[dict[str, Any]] = (),
    ) -> TargetResponse:
        """Send a conversation and time it.

        Transport failures become an errored :class:`TargetResponse` rather than
        an exception: one dead endpoint must not abort a sweep across a dozen
        others, and "the target errored" is itself a result worth reporting.
        """
        prepared = self.prepare(messages)
        started = time.monotonic()
        try:
            response = self._send(prepared, tools if self.supports_tools else ())
        except TargetError as exc:
            return TargetResponse(
                error=str(exc), latency_ms=(time.monotonic() - started) * 1000
            )
        except Exception as exc:  # noqa: BLE001 - adapters may raise anything
            return TargetResponse(
                error=f"{type(exc).__name__}: {exc}",
                latency_ms=(time.monotonic() - started) * 1000,
            )
        latency = (time.monotonic() - started) * 1000
        text = response.text
        if self.max_output_chars and len(text) > self.max_output_chars:
            text = text[: self.max_output_chars]
        return TargetResponse(
            text=text,
            tool_calls=response.tool_calls,
            finish_reason=response.finish_reason,
            latency_ms=response.latency_ms or latency,
            error=response.error,
            raw=response.raw,
        )

    # -- message preparation ----------------------------------------------- #
    def prepare(self, messages: Sequence[Message]) -> list[Message]:
        """Apply ``system_prompt_mode`` to the conversation."""
        if self.system_prompt_mode == "pass":
            return list(messages)
        systems = [m for m in messages if m.role == "system"]
        rest = [m for m in messages if m.role != "system"]
        if self.system_prompt_mode == "drop" or not systems:
            return rest
        # merge: fold system content into the first non-system turn
        preamble = "\n\n".join(m.content for m in systems)
        if not rest:
            return [Message(role="user", content=preamble)]
        first, *others = rest
        merged = Message(
            role=first.role,
            content=f"{preamble}\n\n{first.content}",
            name=first.name,
            trusted=first.trusted,
            tool_calls=first.tool_calls,
        )
        return [merged, *others]

    def close(self) -> None:
        """Release resources. Default is a no-op."""

    def __enter__(self) -> "Target":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.label!r} endpoint={self.endpoint!r}>"


def require_option(options: dict[str, Any], key: str, plugin: str) -> Any:
    """Fetch a required target option or raise a clear :class:`ConfigError`."""
    if key not in options or options[key] in (None, ""):
        raise ConfigError(f"target {plugin!r} requires option {key!r}")
    return options[key]
