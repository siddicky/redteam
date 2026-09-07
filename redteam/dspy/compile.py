"""Gated DSPy program optimization and versioned artifact writing."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final

from ..core.errors import ConfigError
from ..core.redact import Redactor
from ..core.result import Message, Outcome, Payload, TargetResponse, aggregate_verdicts
from ..core.util import now_iso
from ..detectors import build_detectors
from ..detectors.base import DetectionContext, run_detectors
from ..orchestrators.base import Orchestrator, RunContext, RunPlan
from .bridge import TargetBackedLM, require_dspy
from .orchestrator import _PROGRAM_SCHEMA, _replace_attack_turn
from .program import AttackProgram

_SENTINEL_DETECTORS: Final = frozenset(
    {"marker.echo", "canary.leak", "exfil.url_canary"}
)
_OUTPUT_FIELD_RE: Final = re.compile(
    r"starting with (?:the )?field `\[\[ ## ([a-zA-Z0-9_]+) ## \]\]`"
)


@dataclass(frozen=True, slots=True)
class CompileOptions:
    """Operator-selected settings for one optimization run."""

    program_out: Path
    optimizer: str
    layers: int
    demos: int


@dataclass(frozen=True, slots=True)
class CompileResult:
    """Paths and counters printed by the CLI after a successful compile."""

    artifact: Path
    summary: Path
    requests_issued: int
    exclusions: int


def _trainset(dspy: Any, plan: RunPlan) -> tuple[list[Any], dict[str, Payload], int]:
    examples: list[Any] = []
    payloads: dict[str, Payload] = {}
    objectives: set[str] = set()
    exclusions = 0
    for planned in plan.sendable:
        payload = planned.payload
        eligible = bool(payload.sentinel) and payload.probe != "corpus.custom"
        if not eligible or payload.objective in objectives:
            exclusions += 1
            continue
        objectives.add(payload.objective)
        payloads[payload.payload_id] = payload
        examples.append(
            dspy.Example(
                objective=payload.objective,
                sentinel=payload.sentinel,
                target_id=planned.target_id,
                payload_id=payload.payload_id,
            ).with_inputs("objective", "sentinel")
        )
    return examples, payloads, exclusions


def _preflight_destination(path: Path) -> None:
    created = False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        created = not path.exists()
        with path.open("a", encoding="utf-8"):
            pass
    except OSError as exc:
        raise ConfigError(f"DSPy program destination is not writable: {path}: {exc}") from exc
    finally:
        if created and path.exists():
            path.unlink()


def _redact_state(value: Any, redactor: Redactor) -> Any:
    if isinstance(value, dict):
        sanitized = {
            str(key): _redact_state(item, redactor) for key, item in value.items()
        }
        if "lm" in sanitized:
            sanitized["lm"] = None
        return sanitized
    if isinstance(value, list):
        return [_redact_state(item, redactor) for item in value]
    if isinstance(value, tuple):
        return [_redact_state(item, redactor) for item in value]
    if isinstance(value, str):
        return redactor.apply(value)
    return value


def _normalize_stub_output(messages: list[Message], response: TargetResponse) -> TargetResponse:
    prompt = "\n".join(message.content for message in messages)
    fields = _OUTPUT_FIELD_RE.findall(prompt)
    if not fields or fields[-1] == "attack_message":
        return response
    return replace(
        response,
        text=response.text.replace(
            "[[ ## attack_message ## ]]", f"[[ ## {fields[-1]} ## ]]", 1
        ),
    )


def _seed(value: str) -> int:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % (2**31)


def run(
    orchestrator: Orchestrator,
    plan: RunPlan,
    ctx: RunContext,
    options: CompileOptions,
) -> CompileResult:
    """Optimize an AttackProgram through audited targets and write LM-free JSON."""
    dspy = require_dspy()
    trainset, payloads, exclusions = _trainset(dspy, plan)
    if not trainset:
        raise ConfigError(
            "DSPy compile trainset is empty; select sentinel-bearing registered probes"
        )
    _preflight_destination(options.program_out)

    floor = len(trainset) * options.layers * 3
    headroom = ctx.budget.limit // 2
    if floor > headroom:
        raise ConfigError(
            f"DSPy compile request floor {floor} exceeds 50% budget headroom "
            f"{headroom} (budget ceiling {ctx.budget.limit})"
        )

    synthetic_payload = Payload(
        probe="dspy.compile",
        payload_id="optimizer",
        messages=(),
        objective="Optimize an inert red-team program",
    )
    attack_target = ctx.auxiliary_targets["attack_model"]

    def lm_send(messages: list[Message]) -> TargetResponse:
        response = orchestrator.send_once(
            attack_target, messages, synthetic_payload, ctx
        )
        if attack_target.endpoint == "mock:dspy-stub":
            return _normalize_stub_output(messages, response)
        return response

    def metric(example: Any, prediction: Any, trace: Any = None) -> float:
        del trace
        payload = payloads[str(example.payload_id)]
        attack_message = str(prediction.attack_message)
        runtime_payload = replace(
            payload,
            messages=_replace_attack_turn(payload.messages, attack_message),
            detectors=tuple(
                detector
                for detector in payload.detectors
                if detector in _SENTINEL_DETECTORS
            ),
        )
        response = orchestrator.send_once(
            ctx.targets[str(example.target_id)],
            runtime_payload.messages,
            runtime_payload,
            ctx,
        )
        detectors = build_detectors(
            runtime_payload.detectors,
            options=ctx.config.detector_options,
        )
        verdicts = run_detectors(
            detectors,
            DetectionContext(
                payload=runtime_payload,
                response=response,
                conversation=runtime_payload.messages,
                redactor=ctx.redactor,
            ),
        )
        outcome, _ = aggregate_verdicts(verdicts)
        return round(1.0 if outcome is Outcome.BYPASSED else 0.0, 1)

    seed = _seed(ctx.config.seed)
    threads = max(
        1,
        ctx.authorization.effective_concurrency(ctx.config.concurrency),
    )
    attack_spec = ctx.config.orchestrator_options["attack_model"]
    model_options = attack_spec.get("options") or {}
    model = str(model_options.get("model") or attack_spec.get("id") or "attack_model")
    lm = TargetBackedLM(model=model, send=lm_send)

    try:
        with dspy.context(lm=lm):
            program = AttackProgram(options.layers)
            optimizer = dspy.MIPROv2(
                metric=metric,
                auto="light",
                num_threads=threads,
                seed=seed,
            )
            optimized = optimizer.compile(
                program,
                trainset=trainset,
                max_bootstrapped_demos=options.demos,
                max_labeled_demos=0,
                requires_permission_to_run=False,
            )

        state = _redact_state(optimized.dump_state(), Redactor())
        objectives = sorted(str(example.objective) for example in trainset)
        provenance = {
            "seed": ctx.config.seed,
            "optimizer": options.optimizer,
            "dspy_version": dspy.__version__,
            "dataset_digest": hashlib.sha256(
                json.dumps(objectives, ensure_ascii=False).encode("utf-8")
            ).hexdigest(),
            "layers": options.layers,
            "created_at": now_iso(),
            "num_threads_used": threads,
        }
        artifact = _redact_state(
            {"schema": _PROGRAM_SCHEMA, "provenance": provenance, "state": state},
            Redactor(),
        )
        serialized = json.dumps(artifact, indent=2, ensure_ascii=False) + "\n"
        if "http" in serialized.lower() or "TargetBackedLM" in serialized:
            raise ConfigError(
                "refusing to write DSPy artifact containing an endpoint or custom LM class"
            )
        options.program_out.write_text(serialized, encoding="utf-8")

        summary_path = options.program_out.with_name("compile-summary.json")
        summary = _redact_state(
            {
                "provenance": provenance,
                "trainset_size": len(trainset),
                "exclusions": exclusions,
                "requests_issued": ctx.budget.spent,
                "exit_path": str(options.program_out),
            },
            Redactor(),
        )
        summary_path.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return CompileResult(
            artifact=options.program_out,
            summary=summary_path,
            requests_issued=ctx.budget.spent,
            exclusions=exclusions,
        )
    finally:
        for target in [*ctx.targets.values(), *ctx.auxiliary_targets.values()]:
            target.close()
