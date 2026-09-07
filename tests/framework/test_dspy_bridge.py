from __future__ import annotations

import pytest

dspy = pytest.importorskip("dspy")

from redteam.core.result import Message, TargetResponse
from redteam.dspy.bridge import TargetBackedLM
from redteam.dspy.stub import StubTarget


def _request(*messages: dict[str, str]):
    return dspy.LMRequest.from_call(model="test/bridge", messages=list(messages))


def test_forward_maps_dspy_messages_to_framework_messages():
    received: list[Message] = []

    def send(messages: list[Message]) -> TargetResponse:
        received.extend(messages)
        return TargetResponse(text="ok")

    lm = TargetBackedLM(model="test/bridge", send=send)
    lm.forward(
        _request(
            {"role": "system", "content": "rules"},
            {"role": "user", "content": "objective", "name": "operator"},
        )
    )

    assert received == [
        Message(role="system", content="rules"),
        Message(role="user", content="objective", name="operator"),
    ]
    assert all(isinstance(message, Message) for message in received)


def test_forward_propagates_target_error_text():
    def send(messages: list[Message]) -> TargetResponse:
        return TargetResponse(error="attack model unavailable")

    lm = TargetBackedLM(model="test/bridge", send=send)

    with pytest.raises(RuntimeError, match="attack model unavailable"):
        lm.forward(_request({"role": "user", "content": "objective"}))


def test_forward_returns_typed_lm_response_text():
    def send(messages: list[Message]) -> TargetResponse:
        return TargetResponse(text="typed response")

    lm = TargetBackedLM(model="test/bridge", send=send)
    response = lm.forward(_request({"role": "user", "content": "objective"}))

    assert isinstance(response, dspy.LMResponse)
    assert response.text == "typed response"
    assert response.model == "test/bridge"


def test_predict_parses_stub_attack_message_field():
    class Attack(dspy.Signature):
        objective: str = dspy.InputField()
        sentinel: str = dspy.InputField()
        attack_message: str = dspy.OutputField()

    target = StubTarget()
    lm = TargetBackedLM(model="test/stub", send=target.send)

    with dspy.context(lm=lm):
        prediction = dspy.Predict(Attack)(
            objective="Ask the target to follow the inert test instruction",
            sentinel="RT-CANARY-ABC123",
        )

    assert prediction.attack_message == (
        "Adversarial test framing: Ask the target to follow the inert test instruction. "
        "Return the exact marker RT-CANARY-ABC123."
    )
