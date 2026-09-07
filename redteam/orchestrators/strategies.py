"""The three run strategies.

``sweep``
    Breadth. Every payload × every transform × every target, once. This is the
    default and the right first move against a new system: coverage tells you
    where to look, and a single-turn sweep is cheap enough to re-run in CI.

``crescendo``
    Depth across turns. Walks a probe's escalation ladder one rung at a time and
    stops at the first bypass, so a target that resists to rung four costs four
    requests rather than a fixed budget. The rung at which it broke is the finding.

``adaptive``
    Depth across encodings. Sends the baseline; if it is blocked, retries the same
    objective under successive transforms until one gets through or the depth limit
    is reached. What it buys is not just a bypass but a *boundary*: the plain
    payload was blocked and the base64 one was not, which locates the defect in the
    input filter rather than the model.

All three draw from the same budget and rate ceilings, so switching strategy
changes the shape of the traffic, never its volume cap.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Iterator, Sequence

from ..core.result import (
    AttemptResult,
    Message,
    Outcome,
    Payload,
    TargetResponse,
    assistant,
    user,
)
from ..core.util import now_iso
from ..transforms import Transform, build_transform
from .base import ORCHESTRATORS, Orchestrator, PlannedAttempt, RunContext, RunPlan


# --------------------------------------------------------------------------- #
# Sweep
# --------------------------------------------------------------------------- #
@ORCHESTRATORS.register(
    "sweep",
    summary="Single-turn breadth: every payload against every target once",
)
class SweepOrchestrator(Orchestrator):
    """Breadth-first single-turn sweep."""

    description = "Runs every planned attempt once, in parallel up to the concurrency cap"

    def execute(self, plan: RunPlan, ctx: RunContext) -> Iterator[AttemptResult]:
        def worker(planned: PlannedAttempt) -> AttemptResult:
            started = now_iso()
            target = ctx.targets[planned.target_id]
            payload = planned.payload
            response = self.send_once(target, payload.messages, payload, ctx)
            conversation = list(payload.messages)
            if response.text or response.tool_calls:
                conversation.append(assistant(response.text, response.tool_calls))
            verdicts, outcome, score = self.judge(
                payload, response, conversation, ctx
            )
            return self.result_for(
                planned,
                payload=payload,
                conversation=conversation,
                response=response,
                verdicts=verdicts,
                outcome=outcome,
                score=score,
                started_at=started,
            )

        yield from self.run_in_parallel(plan, ctx, worker)


# --------------------------------------------------------------------------- #
# Crescendo
# --------------------------------------------------------------------------- #
@ORCHESTRATORS.register(
    "crescendo",
    summary="Multi-turn escalation: walk a ladder and stop at the first bypass",
)
class CrescendoOrchestrator(Orchestrator):
    """Multi-turn escalation.

    Options:

    ``max_turns``
        Cap on rungs sent per attempt, default 8. Bounds the request cost of a
        ladder regardless of how long the probe's ladder is.
    ``stop_on_bypass``
        Default true. Continuing past a bypass spends requests to learn nothing —
        the guardrail already failed.
    """

    description = "Sends a probe's ladder turn by turn, stopping when the guardrail fails"

    def execute(self, plan: RunPlan, ctx: RunContext) -> Iterator[AttemptResult]:
        max_turns = int(self.options.get("max_turns", 8))
        stop_on_bypass = bool(self.options.get("stop_on_bypass", True))

        def worker(planned: PlannedAttempt) -> AttemptResult:
            started = now_iso()
            target = ctx.targets[planned.target_id]
            payload = planned.payload
            ladder: Sequence[str] = payload.metadata.get("ladder") or [
                m.content for m in payload.messages if m.role == "user"
            ]
            conversation: list[Message] = [
                m for m in payload.messages if m.role == "system"
            ]

            response = None
            verdicts: tuple = ()
            outcome = Outcome.INCONCLUSIVE
            score = 0.0
            turns = 0

            for rung_index, rung in enumerate(ladder[:max_turns], start=1):
                conversation.append(user(rung))
                response = self.send_once(target, conversation, payload, ctx)
                turns = rung_index
                if response.text or response.tool_calls:
                    conversation.append(assistant(response.text, response.tool_calls))
                if response.error:
                    break
                verdicts, outcome, score = self.judge(
                    payload, response, conversation, ctx
                )
                if outcome.is_finding and stop_on_bypass:
                    break

            # Record which rung broke it: "bypassed on turn 4 of 4" and "bypassed on
            # turn 1 of 4" describe very different systems.
            annotated = payload
            if turns:
                annotated = replace(
                    payload,
                    metadata={
                        **payload.metadata,
                        "turns_sent": turns,
                        "ladder_length": len(ladder),
                        "bypassed_on_turn": turns if outcome.is_finding else None,
                    },
                )

            return self.result_for(
                planned,
                payload=annotated,
                conversation=conversation,
                response=response or TargetResponse(error="no turns were sent"),
                verdicts=verdicts,
                outcome=outcome,
                score=score,
                started_at=started,
                turns=turns or 1,
            )

        yield from self.run_in_parallel(plan, ctx, worker)


# --------------------------------------------------------------------------- #
# Adaptive
# --------------------------------------------------------------------------- #
#: Escalation order for the adaptive strategy: cheapest and least conspicuous
#: first, so the earliest success is also the most useful finding. A bypass at
#: ``pad.noise`` says the inspection is length-bounded; one that needs
#: ``encoding.base64`` says it does not normalise.
DEFAULT_ESCALATION: tuple[str, ...] = (
    "pad.noise",
    "wrap.markdown_comment",
    "wrap.json",
    "unicode.zero_width",
    "unicode.homoglyph",
    "encoding.base64",
    "encoding.rot13",
)


@ORCHESTRATORS.register(
    "adaptive",
    summary="Escalate transforms on a blocked payload until one gets through",
)
class AdaptiveOrchestrator(Orchestrator):
    """Feedback-guided transform escalation.

    Options:

    ``escalation``
        Ordered transform ids to try, default :data:`DEFAULT_ESCALATION`.
    ``max_depth``
        Transforms attempted per payload after the baseline, default 4.
    ``escalate_on``
        Which baseline outcomes trigger escalation: ``blocked`` (default) or
        ``blocked,inconclusive``. Escalating an inconclusive baseline is sometimes
        right and always costs more requests, so it is opt-in.

    Deterministic: the order is fixed, so the same seed and target reproduce the
    same escalation path. The plan reports only the baseline attempts, and the run
    notes record the extra requests escalation actually spent — a plan that
    understated its own request count would defeat the point of ``redteam plan``.
    """

    description = "Retries blocked payloads under successively stronger transforms"

    def execute(self, plan: RunPlan, ctx: RunContext) -> Iterator[AttemptResult]:
        escalation: Sequence[str] = tuple(
            self.options.get("escalation") or DEFAULT_ESCALATION
        )
        max_depth = int(self.options.get("max_depth", 4))
        escalate_on = {
            token.strip()
            for token in str(self.options.get("escalate_on", "blocked")).split(",")
            if token.strip()
        }
        transforms: list[Transform] = [build_transform(t) for t in escalation[:max_depth]]
        extra_requests = 0

        def worker(planned: PlannedAttempt) -> AttemptResult:
            nonlocal extra_requests
            started = now_iso()
            target = ctx.targets[planned.target_id]
            baseline = planned.payload

            attempted: list[str] = []
            best: AttemptResult | None = None

            candidates: list[tuple[tuple[str, ...], Payload]] = [
                (planned.transform_ids, baseline)
            ]
            for transform in transforms:
                candidates.append(
                    (
                        tuple(t for t in planned.transform_ids if t != "identity")
                        + (transform.id,),
                        transform.mutate(baseline),
                    )
                )

            for depth, (transform_ids, payload) in enumerate(candidates):
                if depth > 0:
                    extra_requests += 1
                attempted.append("+".join(transform_ids) or "identity")
                response = self.send_once(target, payload.messages, payload, ctx)
                conversation = list(payload.messages)
                if response.text or response.tool_calls:
                    conversation.append(assistant(response.text, response.tool_calls))
                verdicts, outcome, score = self.judge(
                    payload, response, conversation, ctx
                )
                candidate_plan = PlannedAttempt(
                    target_id=planned.target_id,
                    endpoint=planned.endpoint,
                    payload=payload,
                    transform_ids=transform_ids,
                )
                result = self.result_for(
                    candidate_plan,
                    payload=payload,
                    conversation=conversation,
                    response=response,
                    verdicts=verdicts,
                    outcome=outcome,
                    score=score,
                    started_at=started,
                )
                if best is None or _prefer(result, best):
                    best = result
                if outcome.is_finding:
                    note = (
                        f"adaptive: {payload.probe}/{payload.payload_id} bypassed at "
                        f"depth {depth} via {attempted[-1]} "
                        f"(tried: {', '.join(attempted)})"
                    )
                    if note not in ctx.notes:
                        ctx.notes.append(note)
                    return result
                if depth == 0 and outcome.value not in escalate_on:
                    return result

            assert best is not None  # at least the baseline ran
            return best

        yield from self.run_in_parallel(plan, ctx, worker)

        if extra_requests:
            ctx.notes.append(
                f"adaptive escalation issued {extra_requests} request(s) beyond the "
                f"planned baseline attempts"
            )


def _prefer(candidate: AttemptResult, incumbent: AttemptResult) -> bool:
    """Keep the most informative result when nothing bypassed.

    A confident block beats an inconclusive one: "the target refused" is a finding
    about the target, while "we could not tell" is a finding about our tooling.
    """
    order = {
        Outcome.BYPASSED: 0,
        Outcome.BLOCKED: 1,
        Outcome.INCONCLUSIVE: 2,
        Outcome.ERROR: 3,
        Outcome.SKIPPED: 4,
    }
    return order[candidate.outcome] < order[incumbent.outcome]
