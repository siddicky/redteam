"""Dependency-free deterministic target for offline DSPy exercises."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..core.result import Message, TargetResponse
from ..targets.base import TARGETS, Target


def _field(content: str, name: str) -> str:
    marker = f"[[ ## {name} ## ]]"
    _, found, remainder = content.partition(marker)
    if not found:
        return ""
    value = remainder.lstrip("\n")
    for separator in ("\n\n[[ ##", "\n\nRespond with"):
        value = value.partition(separator)[0]
    return value.strip()


@TARGETS.register(
    "dspy.stub",
    summary="Offline deterministic attack-model simulator",
    tags={"offline", "dspy"},
)
class StubTarget(Target):
    """Return a structured, sentinel-preserving attack message without DSPy."""

    def __init__(self, *, drop_sentinel: bool = False, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.drop_sentinel = bool(drop_sentinel)

    @property
    def endpoint(self) -> str:
        return "mock:dspy-stub"

    def _send(
        self,
        messages: Sequence[Message],
        tools: Sequence[dict[str, Any]],
    ) -> TargetResponse:
        user_content = next(
            (message.content for message in reversed(messages) if message.role == "user"),
            "",
        )
        objective = _field(user_content, "objective") or user_content
        sentinel = "" if self.drop_sentinel else _field(user_content, "sentinel")
        attack_message = f"Adversarial test framing: {objective}."
        if sentinel:
            attack_message += f" Return the exact marker {sentinel}."
        return TargetResponse(
            text=(
                "[[ ## attack_message ## ]]\n"
                f"{attack_message}\n\n"
                "[[ ## completed ## ]]"
            )
        )
