"""Budgeted DSPy Attack/Refine orchestration over inert objectives."""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from ..core.config import RunConfig, TargetConfig
from ..core.errors import ConfigError
from ..core.result import (
    AttemptResult,
    Message,
    Outcome,
    Payload,
    TargetResponse,
    Verdict,
    assistant,
)
from ..core.util import now_iso
from ..orchestrators.base import (
    ORCHESTRATORS,
    Orchestrator,
    PlannedAttempt,
    RunContext,
    RunPlan,
)
from ..policy.authorization import Authorization
from ..probes.base import Probe, ProbeContext
from ..targets.base import Target
from ..transforms import Transform

_CARRIER_SKIP = (
    "dspy.redteamer composes only with the identity transform — carrier semantics "
    "must stay attributable to their encoding"
)
_ROLE_NOTE = (
    "dspy.redteamer issues up to layers×3 requests per attempt (1 target + 2 "
    "attack-model per layer), all budget- and rate-counted via send_once; "
    "judge-detector requests additional when configured"
)
_PROGRAM_SCHEMA = "redteam.dspy.program.v1"


def _generative(payload: Payload) -> bool:
    return bool(payload.sentinel) and payload.probe != "corpus.custom"


def _replace_attack_turn(
    messages: Sequence[Message], attack_message: str
) -> tuple[Message, ...]:
    indices = [index for index, message in enumerate(messages) if not message.trusted]
    if not indices:
        indices = [
            index for index, message in enumerate(messages) if message.role == "user"
        ]
    if not indices:
        raise ConfigError("dspy.redteamer payload has no attack-bearing user turn")
    index = indices[-1]
    original = messages[index]
    replacement = Message(
        role=original.role,
        content=attack_message,
        name=original.name,
        trusted=original.trusted,
        tool_calls=original.tool_calls,
    )
    rebuilt = list(messages)
    rebuilt[index] = replacement
    return tuple(rebuilt)


@ORCHESTRATORS.register(
    "dspy.redteamer",
    summary="DSPy Attack/Refine red-teamer over inert objectives",
    tags={"dspy"},
)
class DspyRedteamer(Orchestrator):
    description: str = "Runs a budgeted DSPy Attack/Refine loop over inert objectives"

    def __init__(self, **options: Any) -> None:
        super().__init__(**options)
        attack_model = options.get("attack_model")
        if not isinstance(attack_model, dict) or not attack_model:
            raise ConfigError(
                "orchestrator 'dspy.redteamer' needs an attack model. Add it to "
                "your run config:\n"
                '  "orchestrator_options": {\n'
                '    "attack_model": {"plugin": "http.openai_compat", "options": {\n'
                '      "url": "<endpoint>", "model": "<attack-model>",\n'
                '      "api_key": "${env:ATTACK_MODEL_KEY}"}}\n'
                "  }\n"
                "The attack-model endpoint must also be in your authorization scope."
            )
        self._attack_model = TargetConfig.from_dict(
            {"id": "attack_model", **attack_model}
        )
        try:
            self._layers = int(options.get("layers", 3))
        except (TypeError, ValueError) as exc:
            raise ConfigError("dspy.redteamer layers must be an integer") from exc
        if self._layers < 1:
            raise ConfigError("dspy.redteamer layers must be at least 1")
        self._program_path = str(options.get("program") or "")
        self._program = None
        self._lm = None

        from .bridge import require_dspy

        require_dspy()

    def auxiliary_targets(self) -> dict[str, TargetConfig]:
        return {"attack_model": self._attack_model}

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
        plan = super().plan(
            config,
            authorization,
            targets=targets,
            probes=probes,
            transforms=transforms,
            probe_ctx=probe_ctx,
        )
        attempts: list[PlannedAttempt] = []
        non_generative = 0
        for planned in plan.attempts:
            if planned.transform_ids != ("identity",):
                attempts.append(replace(planned, skip_reason=_CARRIER_SKIP))
            elif planned.skipped:
                attempts.append(planned)
            elif _generative(planned.payload):
                payload = replace(
                    planned.payload,
                    metadata={
                        **planned.payload.metadata,
                        "ladder": list(range(self._layers * 3)),
                    },
                )
                attempts.append(replace(planned, payload=payload))
            else:
                non_generative += 1
                attempts.append(planned)
        plan.attempts = attempts
        if non_generative:
            plan.notes.append(
                f"{non_generative} non-generative payload(s) execute un-reframed; "
                "generative optimization is restricted to inert sentinel objectives "
                "from registered probes"
            )
        plan.notes.append(_ROLE_NOTE)
        return plan

    def execute(self, plan: RunPlan, ctx: RunContext) -> Iterator[AttemptResult]:
        from .bridge import TargetBackedLM, require_dspy
        from .program import AttackProgram

        dspy = require_dspy()
        self._program = AttackProgram(self._layers)
        if self._program_path:
            try:
                with Path(self._program_path).open(encoding="utf-8") as artifact:
                    state = json.load(artifact)
            except (OSError, json.JSONDecodeError) as exc:
                raise ConfigError(
                    f"could not load DSPy program artifact {self._program_path!r}: {exc}"
                ) from exc
            if state.get("schema") != _PROGRAM_SCHEMA:
                raise ConfigError(
                    f"DSPy program artifact must use schema {_PROGRAM_SCHEMA!r}"
                )
            self._program.load_state(state["state"])

        synthetic_payload = Payload(
            probe=self.id,
            payload_id="attack-model",
            messages=(),
            objective="Generate or refine an inert red-team attempt",
            metadata={},
        )

        def lm_send(messages: list[Message]) -> TargetResponse:
            response = self.send_once(
                ctx.auxiliary_targets["attack_model"],
                messages,
                synthetic_payload,
                ctx,
            )
            return self._normalize_stub_refinement(messages, response)

        model = str(
            self._attack_model.options.get("model") or self._attack_model.id
        )
        self._lm = TargetBackedLM(model=model, send=lm_send)

        def worker(planned: PlannedAttempt) -> AttemptResult:
            if not _generative(planned.payload):
                return self._execute_unreframed(planned, ctx)
            return self._execute_generative(planned, ctx, dspy)

        yield from self.run_in_parallel(plan, ctx, worker)

    def _execute_unreframed(
        self, planned: PlannedAttempt, ctx: RunContext
    ) -> AttemptResult:
        started = now_iso()
        payload = planned.payload
        response = self.send_once(
            ctx.targets[planned.target_id], payload.messages, payload, ctx
        )
        conversation = list(payload.messages)
        if response.text or response.tool_calls:
            conversation.append(assistant(response.text, response.tool_calls))
        verdicts, outcome, score = self.judge(payload, response, conversation, ctx)
        return self.result_for(
            planned,
            payload=payload,
            conversation=conversation,
            response=response,
            verdicts=verdicts,
            outcome=outcome,
            score=score,
            started_at=started,
            turns=1,
        )

    def _execute_generative(
        self, planned: PlannedAttempt, ctx: RunContext, dspy: Any
    ) -> AttemptResult:
        started = now_iso()
        payload = planned.payload
        rebuilt_messages = payload.messages
        response = TargetResponse()
        sentinel_dropped = False

        def target_send(attack_message: str) -> str:
            nonlocal rebuilt_messages, response, sentinel_dropped
            rebuilt_messages = _replace_attack_turn(payload.messages, attack_message)
            if payload.sentinel not in attack_message:
                sentinel_dropped = True
                return ""
            response = self.send_once(
                ctx.targets[planned.target_id], rebuilt_messages, payload, ctx
            )
            return response.text

        assert self._program is not None
        with dspy.context(lm=self._lm):
            generated = self._program(
                objective=payload.objective,
                sentinel=payload.sentinel,
                send=target_send,
            )
        rebuilt_messages = _replace_attack_turn(
            payload.messages, generated.attack_message
        )
        runtime_payload = replace(payload, messages=rebuilt_messages)
        if sentinel_dropped or payload.sentinel not in generated.attack_message:
            verdicts = (
                Verdict(
                    detector=self.id,
                    outcome=Outcome.INCONCLUSIVE,
                    rationale="attack model dropped the sentinel",
                ),
            )
            return self.result_for(
                planned,
                payload=runtime_payload,
                conversation=rebuilt_messages,
                response=TargetResponse(),
                verdicts=verdicts,
                outcome=Outcome.INCONCLUSIVE,
                score=0.0,
                started_at=started,
                turns=self._layers,
            )
        conversation = (*rebuilt_messages, assistant(response.text, response.tool_calls))
        verdicts, outcome, score = self.judge(
            runtime_payload, response, conversation, ctx
        )
        return self.result_for(
            planned,
            payload=runtime_payload,
            conversation=conversation,
            response=response,
            verdicts=verdicts,
            outcome=outcome,
            score=score,
            started_at=started,
            turns=self._layers,
        )

    def _normalize_stub_refinement(
        self, messages: Sequence[Message], response: TargetResponse
    ) -> TargetResponse:
        if self._attack_model.plugin != "dspy.stub":
            return response
        prompt = "\n".join(message.content for message in messages)
        if "starting with the field `[[ ## critique ## ]]`" not in prompt:
            return response
        return replace(
            response,
            text=response.text.replace(
                "[[ ## attack_message ## ]]", "[[ ## critique ## ]]", 1
            ),
        )
