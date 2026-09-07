"""Orchestration: turning a config into a plan, and a plan into a run.

The split between *plan* and *execute* is the most important structural decision
in the framework. A plan is computed with no network access, is fully
deterministic from the run seed, and is printable — so ``redteam plan`` shows an
operator exactly what would be sent, against which endpoints, how many requests it
is, and which attempts would be skipped and why. Approving a red-team run should
not require running it.

Execution then walks the plan under three ceilings, all of them derived from the
authorization record rather than the config: the attempt budget, the request rate,
and the concurrency limit. Where the config asks for more than the authorization
allows, the authorization wins and the run notes say so.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Sequence

from ..core.config import RunConfig, TargetConfig
from ..core.errors import BudgetExceeded, ConfigError
from ..core.ratelimit import Budget, NullRateLimiter, RateLimiter
from ..core.redact import Redactor
from ..core.registry import Registry
from ..core.result import (
    AttemptResult,
    Message,
    Outcome,
    Payload,
    RunResult,
    TargetResponse,
    Verdict,
    aggregate_verdicts,
)
from ..core.sentinel import SentinelFactory
from ..core.util import attempt_id, new_run_id, now_iso
from ..detectors import (
    DetectionContext,
    Detector,
    build_detectors,
    close_detectors,
    judge_endpoints,
    run_detectors,
)
from ..policy.authorization import Authorization, is_offline_endpoint
from ..probes import ProbeContext, generate_payloads, select_probes
from ..probes.base import Probe
from ..targets import Target, build_target
from ..transforms import Transform, select_transforms

#: Registry of orchestrators, keyed by id (``sweep``, ``crescendo``, ``adaptive``).
ORCHESTRATORS: Registry["Orchestrator"] = Registry("orchestrator")


# --------------------------------------------------------------------------- #
# The plan
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class PlannedAttempt:
    """One attempt, before it is sent."""

    target_id: str
    endpoint: str
    payload: Payload
    transform_ids: tuple[str, ...]
    skip_reason: str = ""

    @property
    def skipped(self) -> bool:
        return bool(self.skip_reason)

    @property
    def id(self) -> str:
        return attempt_id(
            self.target_id,
            self.payload.probe,
            self.payload.payload_id,
            *self.transform_ids,
        )

    def to_dict(self, *, include_text: bool = False) -> dict:
        out: dict[str, Any] = {
            "attempt_id": self.id,
            "target": self.target_id,
            "endpoint": self.endpoint,
            "probe": self.payload.probe,
            "payload_id": self.payload.payload_id,
            "transforms": list(self.transform_ids),
            "risk": self.payload.risk.value,
            "carrier": self.payload.carrier,
            "technique": self.payload.technique,
            "detectors": list(self.payload.detectors),
        }
        if self.skip_reason:
            out["skipped"] = self.skip_reason
        if include_text:
            out["messages"] = [m.to_dict() for m in self.payload.messages]
        return out


@dataclass
class RunPlan:
    """The complete, reviewable description of a run."""

    orchestrator: str
    attempts: list[PlannedAttempt] = field(default_factory=list)
    targets: dict[str, str] = field(default_factory=dict)  # id -> endpoint
    probes: list[str] = field(default_factory=list)
    transforms: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    seed: str = ""
    truncated: bool = False

    @property
    def sendable(self) -> list[PlannedAttempt]:
        return [a for a in self.attempts if not a.skipped]

    @property
    def skipped(self) -> list[PlannedAttempt]:
        return [a for a in self.attempts if a.skipped]

    def request_estimate(self) -> int:
        """Requests this plan will issue.

        Multi-turn attempts cost one request per rung, so the naive "one attempt,
        one request" count understates a crescendo run by 4–5x. An operator sizing
        the load on someone's staging system needs the real number.
        """
        total = 0
        for attempt in self.sendable:
            total += max(1, len(attempt.payload.metadata.get("ladder") or [1]))
        return total

    def to_dict(self, *, include_text: bool = False) -> dict:
        return {
            "orchestrator": self.orchestrator,
            "seed": self.seed,
            "targets": self.targets,
            "probes": self.probes,
            "transforms": self.transforms,
            "counts": {
                "attempts": len(self.attempts),
                "sendable": len(self.sendable),
                "skipped": len(self.skipped),
                "estimated_requests": self.request_estimate(),
            },
            "truncated": self.truncated,
            "notes": self.notes,
            "attempts_detail": [
                a.to_dict(include_text=include_text) for a in self.attempts
            ],
        }


# --------------------------------------------------------------------------- #
# Runner context
# --------------------------------------------------------------------------- #
@dataclass
class RunContext:
    """Everything an orchestrator needs to execute a plan."""

    config: RunConfig
    authorization: Authorization
    targets: dict[str, Target]
    budget: Budget
    limiter: RateLimiter
    redactor: Redactor
    probe_ctx: ProbeContext
    auxiliary_targets: dict[str, Target] = field(default_factory=dict)
    detector_cache: dict[str, Detector] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    on_attempt: Callable[[AttemptResult], None] | None = None

    def detectors_for(self, payload: Payload) -> list[Detector]:
        ids = list(payload.detectors) or ["marker.echo", "refusal.heuristic"]
        for extra in self.config.detectors:
            if extra not in ids:
                ids.append(extra)
        return build_detectors(
            ids, options=self.config.detector_options, cache=self.detector_cache
        )


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
class Orchestrator(ABC):
    """Base class for run strategies."""

    #: Set by :meth:`Registry.register`.
    id: str = ""
    #: One-line description for ``redteam list orchestrators``.
    description: str = ""

    def __init__(self, **options: Any) -> None:
        self.options = options

    def auxiliary_targets(self) -> dict[str, TargetConfig]:
        """Return outbound models used by the orchestrator itself."""
        return {}

    # -- planning ---------------------------------------------------------- #
    def plan(
        self,
        config: RunConfig,
        authorization: Authorization,
        *,
        targets: dict[str, Target],
        probes: Sequence[Probe],
        transforms: Sequence[Transform],
        probe_ctx: ProbeContext,
    ) -> RunPlan:
        """Enumerate every attempt, marking the ones that cannot run.

        Skips are recorded rather than dropped. A probe that could not run against
        a target is not evidence that the target is safe, and a plan that quietly
        omitted it would imply otherwise.
        """
        plan = RunPlan(
            orchestrator=self.id,
            targets={tid: t.endpoint for tid, t in targets.items()},
            probes=[p.id for p in probes],
            transforms=[t.id for t in transforms],
            seed=probe_ctx.seed,
        )
        limit = authorization.effective_attempts(config.max_attempts)

        for target_id, target in targets.items():
            for probe, payload in generate_payloads(probes, probe_ctx):
                skip = self._skip_reason(probe, payload, target)
                for transform in transforms:
                    if transform.id != "identity" and skip:
                        continue  # one skip record per payload is enough
                    mutated = transform.mutate(payload)
                    plan.attempts.append(
                        PlannedAttempt(
                            target_id=target_id,
                            endpoint=target.endpoint,
                            payload=mutated,
                            transform_ids=(transform.id,),
                            skip_reason=skip,
                        )
                    )

        if limit and len(plan.sendable) > limit:
            keep = limit
            trimmed: list[PlannedAttempt] = []
            sent = 0
            for attempt in plan.attempts:
                if attempt.skipped:
                    trimmed.append(attempt)
                    continue
                if sent < keep:
                    trimmed.append(attempt)
                    sent += 1
            dropped = len(plan.sendable) - sent
            plan.attempts = trimmed
            plan.truncated = True
            plan.notes.append(
                f"plan truncated to the {limit}-attempt ceiling; {dropped} attempt(s) "
                f"were dropped and are NOT covered by this run"
            )
        return plan

    def _skip_reason(self, probe: Probe, payload: Payload, target: Target) -> str:
        if probe.requires_orchestrator and self.id not in probe.requires_orchestrator:
            return (
                f"probe requires the {'/'.join(probe.requires_orchestrator)} "
                f"orchestrator; running it under {self.id} would not test what it "
                f"claims to test"
            )
        needs_system = probe.requires_system_prompt or payload.metadata.get(
            "requires_system_prompt"
        )
        if needs_system and target.system_prompt_mode == "drop":
            return (
                "probe plants a value in the system prompt, but this target's "
                "system_prompt_mode is 'drop' — the probe cannot run, so its result "
                "is unknown rather than passing"
            )
        if payload.metadata.get("tools") and not target.supports_tools:
            return (
                "payload declares tools but this target adapter cannot offer tool "
                "schemas; a tool-call bypass could not be observed"
            )
        return ""

    # -- execution --------------------------------------------------------- #
    @abstractmethod
    def execute(self, plan: RunPlan, ctx: RunContext) -> Iterator[AttemptResult]:
        """Run the plan, yielding results as they complete."""

    # -- shared machinery -------------------------------------------------- #
    def send_once(
        self,
        target: Target,
        messages: Sequence[Message],
        payload: Payload,
        ctx: RunContext,
    ) -> TargetResponse:
        """One rate-limited, budgeted request."""
        ctx.budget.take(1)
        ctx.limiter.acquire()
        tools = payload.metadata.get("tools") or []
        return target.send(messages, tools=tools)

    def judge(
        self,
        payload: Payload,
        response: TargetResponse,
        conversation: Sequence[Message],
        ctx: RunContext,
    ) -> tuple[tuple[Verdict, ...], Outcome, float]:
        """Run the payload's detectors and aggregate their verdicts."""
        detection = DetectionContext(
            payload=payload,
            response=response,
            conversation=tuple(conversation),
            redactor=ctx.redactor,
        )
        verdicts = run_detectors(ctx.detectors_for(payload), detection)
        outcome, score = aggregate_verdicts(verdicts)
        return verdicts, outcome, score

    def result_for(
        self,
        planned: PlannedAttempt,
        *,
        payload: Payload,
        conversation: Sequence[Message],
        response: TargetResponse,
        verdicts: Sequence[Verdict],
        outcome: Outcome,
        score: float,
        started_at: str,
        turns: int = 1,
    ) -> AttemptResult:
        return AttemptResult(
            attempt_id=planned.id,
            target=planned.target_id,
            payload=payload,
            transforms=planned.transform_ids,
            conversation=tuple(conversation),
            response=response,
            verdicts=tuple(verdicts),
            outcome=outcome,
            score=score,
            started_at=started_at,
            finished_at=now_iso(),
            turns=turns,
            error=response.error,
        )

    def skipped_result(self, planned: PlannedAttempt) -> AttemptResult:
        return AttemptResult(
            attempt_id=planned.id,
            target=planned.target_id,
            payload=planned.payload,
            transforms=planned.transform_ids,
            conversation=(),
            response=TargetResponse(),
            verdicts=(
                Verdict(
                    detector="orchestrator",
                    outcome=Outcome.SKIPPED,
                    rationale=planned.skip_reason,
                ),
            ),
            outcome=Outcome.SKIPPED,
            score=0.0,
            started_at=now_iso(),
            finished_at=now_iso(),
        )

    def run_in_parallel(
        self,
        plan: RunPlan,
        ctx: RunContext,
        worker: Callable[[PlannedAttempt], AttemptResult],
    ) -> Iterator[AttemptResult]:
        """Execute attempts, honouring the concurrency ceiling.

        Skips are emitted first and cost nothing. The budget is checked inside
        :meth:`send_once`, so a run that exhausts it stops sending immediately
        instead of queueing work it is not allowed to do.
        """
        for planned in plan.skipped:
            yield self.skipped_result(planned)

        sendable = plan.sendable
        workers = ctx.authorization.effective_concurrency(ctx.config.concurrency)
        if workers <= 1 or len(sendable) <= 1:
            for planned in sendable:
                result = self._guarded(worker, planned, ctx)
                if result is None:
                    return
                yield result
            return

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(self._guarded, worker, planned, ctx) for planned in sendable]
            for future in futures:
                result = future.result()
                if result is not None:
                    yield result

    def _guarded(
        self,
        worker: Callable[[PlannedAttempt], AttemptResult],
        planned: PlannedAttempt,
        ctx: RunContext,
    ) -> AttemptResult | None:
        """Run one attempt, converting budget exhaustion into a stop signal."""
        try:
            result = worker(planned)
        except BudgetExceeded as exc:
            note = str(exc)
            if note not in ctx.notes:
                ctx.notes.append(note)
            return None
        if ctx.on_attempt is not None:
            ctx.on_attempt(result)
        return result


# --------------------------------------------------------------------------- #
# Top-level driver
# --------------------------------------------------------------------------- #
def prepare_run(
    config: RunConfig,
    authorization: Authorization,
    *,
    seed: str | None = None,
    max_payloads_per_probe: int = 0,
    corpus_path: str = "",
    probe_options: dict[str, dict[str, Any]] | None = None,
    on_attempt: Callable[[AttemptResult], None] | None = None,
) -> tuple[Orchestrator, RunPlan, RunContext]:
    """Build the orchestrator, plan, and context for a run.

    Every outbound endpoint — targets *and* judge detectors — passes the
    authorization gate here, before anything is instantiated further. The gate
    raises, so an unauthorized run cannot get as far as its first request.
    """
    if not config.targets:
        raise ConfigError("config declares no targets; nothing to test")

    orchestrator = ORCHESTRATORS.create(
        config.orchestrator, **config.orchestrator_options
    )
    run_seed = seed or config.seed

    targets: dict[str, Target] = {}
    for target_config in config.targets:
        target = build_target(target_config, timeout=config.timeout)
        authorization.authorize(target.endpoint)
        targets[target_config.id] = target

    auxiliary: dict[str, Target] = {}
    auxiliary_notes: list[str] = []
    for name, target_config in orchestrator.auxiliary_targets().items():
        target = build_target(target_config, timeout=config.timeout)
        authorization.authorize(target.endpoint)
        auxiliary[name] = target
        auxiliary_notes.append(f"auxiliary endpoint authorized ({name}): {target.endpoint}")

    probes = select_probes(
        config.probes,
        include_tags=config.include_tags,
        exclude_tags=config.exclude_tags,
        probe_options=probe_options or config.probe_options,
    )
    if config.min_risk is not None:
        probes = [p for p in probes if p.risk.at_least(config.min_risk)]
        if not probes:
            raise ConfigError(
                f"no probes remain at min_risk={config.min_risk.value}"
            )
    transforms = select_transforms(config.transforms)

    probe_ctx = ProbeContext(
        sentinels=SentinelFactory(seed=run_seed),
        seed=run_seed,
        max_payloads=max_payloads_per_probe,
        corpus_path=corpus_path,
    )

    plan = orchestrator.plan(
        config,
        authorization,
        targets=targets,
        probes=probes,
        transforms=transforms,
        probe_ctx=probe_ctx,
    )

    notes: list[str] = [*plan.notes, *auxiliary_notes]
    effective_attempts = authorization.effective_attempts(config.max_attempts)
    effective_rate = authorization.effective_rate(config.requests_per_minute)
    effective_concurrency = authorization.effective_concurrency(config.concurrency)
    if config.max_attempts and effective_attempts < config.max_attempts:
        notes.append(
            f"max_attempts lowered from {config.max_attempts} to {effective_attempts} "
            f"by the authorization record"
        )
    if effective_rate < config.requests_per_minute:
        notes.append(
            f"request rate lowered from {config.requests_per_minute:g} to "
            f"{effective_rate:g} req/min by the authorization record"
        )
    if effective_concurrency < config.concurrency:
        notes.append(
            f"concurrency lowered from {config.concurrency} to "
            f"{effective_concurrency} by the authorization record"
        )

    # Rate limiting exists to protect someone else's system. When every target is
    # offline there is no such system, and throttling the mock would only make the
    # test suite and the demo slow enough that nobody runs them.
    all_offline = all(
        is_offline_endpoint(t.endpoint) for t in [*targets.values(), *auxiliary.values()]
    )
    limiter: RateLimiter = NullRateLimiter() if all_offline else RateLimiter(effective_rate)
    if all_offline:
        notes.append(
            "all targets are offline (no network egress); request rate limiting is "
            "not applied"
        )

    ctx = RunContext(
        config=config,
        authorization=authorization,
        targets=targets,
        budget=Budget(limit=effective_attempts),
        limiter=limiter,
        redactor=Redactor() if config.redact_artifacts else Redactor(
            redact_secrets=False, redact_emails=False, redact_cards=False
        ),
        probe_ctx=probe_ctx,
        auxiliary_targets=auxiliary,
        notes=notes,
        on_attempt=on_attempt,
    )

    # Judge detectors reach the network too, so authorize them before the run —
    # not on first use, halfway through.
    sample_ids = sorted(
        {d for attempt in plan.sendable for d in attempt.payload.detectors}
        | set(config.detectors)
    )
    detectors = build_detectors(
        sample_ids, options=config.detector_options, cache=ctx.detector_cache
    )
    for endpoint in judge_endpoints(detectors):
        authorization.authorize(endpoint)
        ctx.notes.append(f"judge endpoint authorized: {endpoint}")

    return orchestrator, plan, ctx


def execute_run(
    orchestrator: Orchestrator,
    plan: RunPlan,
    ctx: RunContext,
    *,
    run_id: str = "",
) -> RunResult:
    """Execute a prepared plan and assemble the :class:`RunResult`."""
    result = RunResult(
        run_id=run_id or new_run_id(ctx.probe_ctx.seed),
        started_at=now_iso(),
        orchestrator=orchestrator.id,
        targets=list(ctx.targets),
        probes=list(plan.probes),
        authorization=ctx.authorization.record(),
        config=ctx.config.to_dict(),
        truncated=plan.truncated,
    )
    try:
        for attempt in orchestrator.execute(plan, ctx):
            result.add(attempt)
    finally:
        result.finished_at = now_iso()
        result.notes = list(ctx.notes)
        close_detectors(list(ctx.detector_cache.values()))
        for target in ctx.targets.values():
            target.close()
        for target in ctx.auxiliary_targets.values():
            target.close()
    return result
