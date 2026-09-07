"""The detector interface.

A detector answers one question about one response: *did the guardrail hold?* It
returns a :class:`~redteam.core.result.Verdict` with an outcome, a confidence, and
evidence.

Three design rules, all of them there because the alternative produces reports
nobody trusts:

**Prefer ground truth over judgement.** Wherever a probe planted a sentinel or a
canary, the detector looks for *that exact value*. Sentinel matching has no false
positives worth worrying about — a 40-bit nonce does not appear by chance — which
is why the probe corpus is built around it. Fuzzy detectors (refusal lexicons,
LLM judges) exist for the cases that cannot be reduced to a token, and their
verdicts are weighted accordingly.

**Never silently guess.** A detector that cannot decide returns
``INCONCLUSIVE``, which the aggregator refuses to count as a pass. Overstating
security is the one failure mode that makes this whole exercise worse than not
running it.

**Explain the call.** Every verdict carries ``evidence`` — a short, redacted
excerpt. A finding an engineer cannot verify from the report is a finding they
will (correctly) ignore.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Sequence

from ..core.redact import Redactor, excerpt
from ..core.registry import Registry
from ..core.result import Message, Outcome, Payload, TargetResponse, Verdict

#: Registry of detectors, keyed by dotted id (``marker.echo``).
DETECTORS: Registry["Detector"] = Registry("detector")


@dataclass
class DetectionContext:
    """Everything a detector may look at.

    Detectors receive the payload as well as the response, because a verdict
    usually depends on what was asked: the sentinel to look for, the tools that
    were off-limits, the canary that was planted.
    """

    payload: Payload
    response: TargetResponse
    conversation: Sequence[Message] = ()
    redactor: Redactor | None = None
    options: dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.options is None:
            self.options = {}

    # -- text views -------------------------------------------------------- #
    @property
    def text(self) -> str:
        """Response text only."""
        return self.response.text or ""

    @property
    def rendered(self) -> str:
        """Response text plus rendered tool calls.

        Most detectors want this: an instruction obeyed through a tool call is
        obeyed, and a detector that only read ``text`` would miss it.
        """
        return self.response.rendered()

    def evidence(self, needle: str = "", width: int = 160) -> tuple[str, ...]:
        """A redacted excerpt of the response, centred on ``needle``."""
        redactor = self.redactor
        if redactor is not None and self.payload.sentinel:
            redactor = redactor.with_preserved(self.payload.sentinel)
        raw = excerpt(self.rendered, needle, width)
        return (redactor.apply(raw) if redactor else raw,)


class Detector(ABC):
    """Base class for detectors."""

    #: Set by :meth:`Registry.register`.
    id: str = ""
    #: One-line description for ``redteam list detectors``.
    description: str = ""
    #: Detectors that need a planted value are skipped when the payload has none,
    #: rather than reporting a pass they did not establish.
    requires_sentinel: bool = False

    def __init__(self, **options: Any) -> None:
        self.options = options

    @abstractmethod
    def inspect(self, ctx: DetectionContext) -> Verdict:
        """Judge one response."""

    # -- helpers ----------------------------------------------------------- #
    def verdict(
        self,
        outcome: Outcome,
        *,
        score: float = 0.0,
        rationale: str = "",
        evidence: Sequence[str] = (),
    ) -> Verdict:
        return Verdict(
            detector=self.id,
            outcome=outcome,
            score=score,
            rationale=rationale,
            evidence=tuple(evidence),
        )

    def bypassed(
        self, rationale: str, *, score: float = 1.0, evidence: Sequence[str] = ()
    ) -> Verdict:
        return self.verdict(
            Outcome.BYPASSED, score=score, rationale=rationale, evidence=evidence
        )

    def blocked(
        self, rationale: str, *, score: float = 0.0, evidence: Sequence[str] = ()
    ) -> Verdict:
        return self.verdict(
            Outcome.BLOCKED, score=score, rationale=rationale, evidence=evidence
        )

    def inconclusive(self, rationale: str, *, evidence: Sequence[str] = ()) -> Verdict:
        return self.verdict(
            Outcome.INCONCLUSIVE, score=0.0, rationale=rationale, evidence=evidence
        )

    def describe(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description
            or (self.__doc__ or "").strip().splitlines()[0],
            "requires_sentinel": self.requires_sentinel,
        }

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.id!r}>"


def run_detectors(
    detectors: Sequence[Detector], ctx: DetectionContext
) -> tuple[Verdict, ...]:
    """Run every detector, tolerating individual failures.

    A detector that raises produces an ``ERROR`` verdict rather than aborting the
    attempt: losing one signal is better than losing the attempt, and the error is
    visible in the report instead of being swallowed.
    """
    verdicts: list[Verdict] = []
    for detector in detectors:
        if detector.requires_sentinel and not ctx.payload.sentinel:
            verdicts.append(
                Verdict(
                    detector=detector.id,
                    outcome=Outcome.INCONCLUSIVE,
                    rationale=(
                        "payload planted no sentinel, so this detector cannot "
                        "establish a result"
                    ),
                )
            )
            continue
        if ctx.response.error:
            verdicts.append(
                Verdict(
                    detector=detector.id,
                    outcome=Outcome.ERROR,
                    rationale=f"target error: {ctx.response.error}",
                )
            )
            continue
        if not ctx.response.text.strip() and not ctx.response.tool_calls:
            # Nothing came back. Every detector would technically "not find" the
            # thing it looks for, and letting that count as BLOCKED would turn a
            # silent target into a clean bill of health. Silence is undecided.
            verdicts.append(
                Verdict(
                    detector=detector.id,
                    outcome=Outcome.INCONCLUSIVE,
                    rationale=(
                        "target returned no content; nothing to inspect, so the "
                        "guardrail was not demonstrated either way"
                    ),
                )
            )
            continue
        try:
            verdicts.append(detector.inspect(ctx))
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            verdicts.append(
                Verdict(
                    detector=detector.id,
                    outcome=Outcome.ERROR,
                    rationale=f"detector raised {type(exc).__name__}: {exc}",
                )
            )
    return tuple(verdicts)
