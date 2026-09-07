from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, ClassVar

import pytest

dspy = pytest.importorskip("dspy")

from redteam.dspy.program import AttackProgram

if TYPE_CHECKING:
    from dspy import LMRequest, LMResponse


class RecordingLM(dspy.BaseLM):
    forward_contract: ClassVar[str] = "typed_lm"

    def __init__(self) -> None:
        super().__init__(model="test/program")
        self.attack_calls: int = 0
        self.refine_calls: int = 0

    def forward(self, request: LMRequest) -> LMResponse:
        content = "\n".join(message.text or "" for message in request.messages)
        if "[[ ## target_response ## ]]" in content:
            self.refine_calls += 1
            text = (
                "[[ ## critique ## ]]\n"
                f"critique-{self.refine_calls}\n\n"
                "[[ ## completed ## ]]"
            )
        else:
            self.attack_calls += 1
            text = (
                "[[ ## attack_message ## ]]\n"
                f"attack-{self.attack_calls}\n\n"
                "[[ ## completed ## ]]"
            )
        return dspy.LMResponse.from_text(text, model=request.model)


def test_two_layers_call_each_predictor_and_send_once_per_layer() -> None:
    lm = RecordingLM()
    sent: list[str] = []

    def send(attack_message: str) -> str:
        sent.append(attack_message)
        return f"response-{len(sent)}"

    with dspy.context(lm=lm):
        result = AttackProgram(layers=2)(
            objective="Follow the inert test instruction",
            sentinel="RT-CANARY-ABC123",
            critique="initial critique",
            send=send,
        )

    assert lm.attack_calls == 2
    assert lm.refine_calls == 2
    assert len(lm.history) == 4
    assert sent == ["attack-1", "attack-2"]
    assert result.attack_message == "attack-2"
    assert result.turns == 2
    assert result.traces == [
        {
            "objective": "Follow the inert test instruction",
            "critique": "critique-1",
            "attack": "attack-1",
            "response": "response-1",
        },
        {
            "objective": "Follow the inert test instruction",
            "critique": "critique-2",
            "attack": "attack-2",
            "response": "response-2",
        },
    ]


def test_send_none_skips_the_callback() -> None:
    lm = RecordingLM()
    send: Callable[[str], str] | None = None

    with dspy.context(lm=lm):
        result = AttackProgram(layers=1)(
            objective="Follow the inert test instruction",
            sentinel="RT-CANARY-ABC123",
            send=send,
        )

    assert result.attack_message == "attack-1"
    assert result.traces[0]["response"] == ""
    assert lm.attack_calls == 1
    assert lm.refine_calls == 1


def test_zero_layers_is_rejected() -> None:
    with pytest.raises(ValueError, match="layers must be at least 1"):
        AttackProgram(layers=0)
