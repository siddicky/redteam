"""Typed DSPy language-model bridge over the framework target seam."""

from __future__ import annotations

import importlib
from collections.abc import Callable
from types import ModuleType
from typing import TYPE_CHECKING, Any

from ..core.errors import ConfigError
from ..core.result import Message, TargetResponse

if TYPE_CHECKING:
    from dspy import LMRequest, LMResponse

try:
    import dspy
except (ImportError, ModuleNotFoundError):
    dspy = None


def require_dspy() -> ModuleType:
    """Load the optional DSPy dependency or name the install extra."""
    global dspy
    if dspy is not None:
        return dspy
    try:
        dspy = importlib.import_module("dspy")
    except ImportError as exc:
        raise ConfigError(
            'DSPy support requires pip install "ai-redteam[dspy]"'
        ) from exc
    return dspy


if dspy is None:

    class TargetBackedLM:
        """Reject construction when the optional DSPy dependency is unavailable."""

        forward_contract = "typed_lm"

        def __init__(
            self,
            model: str,
            send: Callable[[list[Message]], TargetResponse],
            **kwargs: Any,
        ) -> None:
            require_dspy()

else:
    _dspy = dspy
    _DspyBaseLM: Any = _dspy.BaseLM

    class TargetBackedLM(_DspyBaseLM):
        """Execute DSPy model requests through a framework target send callable."""

        forward_contract = "typed_lm"

        def __init__(
            self,
            model: str,
            send: Callable[[list[Message]], TargetResponse],
            **kwargs: Any,
        ) -> None:
            super().__init__(model=model, **kwargs)
            self._send = send

        def forward(self, request: LMRequest) -> LMResponse:
            messages = [
                Message(
                    role=message.role,
                    content=message.text or "",
                    name=message.name or "",
                )
                for message in request.messages
            ]
            response = self._send(messages)
            if response.error:
                raise RuntimeError(response.error)
            return _dspy.LMResponse.from_text(response.text, model=self.model)
