"""Replay target: re-serve the responses from a saved run.

This turns a finished run into a fixture, which buys three things:

* **Detector regression testing.** Change a refusal lexicon and re-score last
  week's run offline. If a previously-confirmed bypass stops being detected, the
  change was a regression, not an improvement.
* **Free re-analysis.** Adding a detector should not cost another round of
  traffic against someone's production system.
* **Reproducible bug reports.** "Run this against ``runs/<id>.json``" is a
  complete reproduction that needs no credentials.

Responses are keyed by payload fingerprint, so the same probe corpus lines up
with the stored run even if the plan order changed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from ..core.errors import ConfigError, TargetError
from ..core.result import Message, RunResult, TargetResponse
from .base import TARGETS, Target


@TARGETS.register(
    "replay.transcript",
    summary="Re-serve responses from a saved run artifact (offline)",
    tags={"offline", "deterministic"},
)
class ReplayTarget(Target):
    """Serve stored responses from a previous run's JSON.

    Options:

    ``path``
        The run artifact to replay. Required.
    ``target``
        When the artifact holds several targets, which one to replay. Defaults to
        the first target seen.
    ``strict``
        With ``True`` (default) an unmatched conversation is an error, so a
        silently-changed probe corpus cannot masquerade as a clean run.
    """

    def __init__(
        self,
        *,
        path: str = "",
        target: str = "",
        strict: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        if not path:
            raise ConfigError(f"target {self.id!r} requires option 'path'")
        self.path = Path(path)
        if not self.path.is_file():
            raise ConfigError(f"replay artifact not found: {self.path}")
        try:
            run = RunResult.from_json(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{self.path}: invalid run JSON — {exc}") from None
        self.source_run_id = run.run_id
        self.replayed_target = target or (run.targets[0] if run.targets else "")
        self.strict = bool(strict)

        self._by_fingerprint: dict[str, TargetResponse] = {}
        self._by_prompt: dict[str, TargetResponse] = {}
        for attempt in run.attempts:
            if self.replayed_target and attempt.target != self.replayed_target:
                continue
            self._by_fingerprint.setdefault(
                attempt.payload.fingerprint, attempt.response
            )
            for prompt, response in _prompt_response_pairs(attempt):
                self._by_prompt.setdefault(_conversation_key(prompt), response)
        if not self._by_fingerprint and not self._by_prompt:
            raise ConfigError(
                f"{self.path}: no attempts for target {self.replayed_target!r}. "
                f"Available: {', '.join(sorted({a.target for a in run.attempts})) or 'none'}"
            )

    @property
    def endpoint(self) -> str:
        return f"replay:{self.path}"

    @property
    def supports_tools(self) -> bool:
        """True: stored tool calls are replayed verbatim.

        The tool *schemas* are ignored — nothing is generated here — but a stored
        response can contain tool calls, so a tool-abuse probe is replayable. Saying
        False would make the orchestrator skip exactly the probes whose findings are
        most worth re-scoring.
        """
        return True

    def describe(self) -> dict[str, Any]:
        out = super().describe()
        out["source_run_id"] = self.source_run_id
        out["replayed_target"] = self.replayed_target
        out["stored_responses"] = len(self._by_prompt)
        return out

    def lookup(self, fingerprint: str) -> TargetResponse | None:
        return self._by_fingerprint.get(fingerprint)

    def _send(
        self, messages: Sequence[Message], tools: Sequence[dict[str, Any]]
    ) -> TargetResponse:
        response = self._by_prompt.get(_conversation_key(messages))
        if response is not None:
            return response
        if self.strict:
            raise TargetError(
                f"no stored response for this prompt in {self.path}. The probe corpus "
                f"or the run seed has changed since the run was recorded, so the "
                f"prompts no longer line up; re-run live, match the original seed, or "
                f"set strict=false to treat misses as empty responses."
            )
        return TargetResponse(text="", finish_reason="replay_miss")


def _prompt_response_pairs(attempt) -> list[tuple[tuple[Message, ...], TargetResponse]]:
    """Split a stored transcript into ``(prompt-as-sent, response)`` pairs.

    Keying on the whole transcript would never match: the stored conversation
    includes the assistant's reply, while a replay request arrives without it. The
    prompt as sent is the prefix *before* each assistant turn.

    Splitting at every assistant turn — not just the last — is what makes multi-turn
    runs replayable: each rung of a crescendo ladder gets its own entry, so the
    ladder can be walked again offline.
    """
    pairs: list[tuple[tuple[Message, ...], TargetResponse]] = []
    conversation = list(attempt.conversation)
    assistant_indices = [i for i, m in enumerate(conversation) if m.role == "assistant"]

    for position, index in enumerate(assistant_indices):
        prompt = tuple(conversation[:index])
        if not prompt:
            continue
        is_last = position == len(assistant_indices) - 1
        if is_last:
            response = attempt.response
        else:
            turn = conversation[index]
            response = TargetResponse(
                text=turn.content,
                tool_calls=turn.tool_calls,
                finish_reason="replay",
            )
        pairs.append((prompt, response))

    # A conversation with no assistant turn at all (an errored attempt) still has a
    # prompt worth serving, so the same plan reproduces the same error.
    if not assistant_indices and conversation:
        pairs.append((tuple(conversation), attempt.response))
    return pairs


def _conversation_key(messages: Sequence[Message]) -> str:
    import hashlib

    blob = json.dumps([m.to_dict() for m in messages], sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
