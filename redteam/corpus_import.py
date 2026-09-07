from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from .core.errors import ConfigError
from .corpus_types import CapturedConversation, CapturedTurn, JsonValue

_JSON_LOADS: Callable[[str], JsonValue] = json.loads


def _generic_conversations(value: JsonValue, source: str) -> list[CapturedConversation]:
    if isinstance(value, dict) and "messages" in value:
        candidates: list[JsonValue] = [value["messages"]]
    elif (
        isinstance(value, list)
        and value
        and all(isinstance(item, dict) and "role" in item for item in value)
    ):
        candidates = [value]
    elif isinstance(value, list):
        candidates = value
    else:
        raise ConfigError(
            f"{source}: expected a conversation ({{'messages': [...]}}), a list "
            + "of conversations, an accepted Arena export, or JSONL"
        )

    conversations: list[CapturedConversation] = []
    for index, item in enumerate(candidates):
        if isinstance(item, dict) and "messages" in item:
            item = item["messages"]
        if not isinstance(item, list):
            raise ConfigError(
                f"{source}: conversation {index} must be a list of "
                + "{'role', 'content'} objects"
            )
        messages: list[CapturedTurn] = []
        for position, message in enumerate(item):
            if (
                not isinstance(message, dict)
                or "role" not in message
                or "content" not in message
            ):
                raise ConfigError(
                    f"{source}: conversation {index} message {position} needs "
                    + "'role' and 'content'"
                )
            messages.append(
                CapturedTurn(
                    role=str(message["role"]),
                    content=str(message["content"]),
                )
            )
        if messages:
            conversations.append(CapturedConversation(messages=tuple(messages)))
    return conversations


def _conversations_from(
    value: JsonValue,
    source: str,
) -> tuple[list[CapturedConversation], bool]:
    if isinstance(value, dict) and (
        "pages" in value or "userSubmissions" in value
    ):
        from .arena_export import load_arena_conversations

        return load_arena_conversations(value, source), True
    return _generic_conversations(value, source), False


def load_captured_conversations(path: Path) -> tuple[list[CapturedConversation], bool]:
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise ConfigError(f"{path}: file is empty")

    try:
        parsed = _JSON_LOADS(text)
    except json.JSONDecodeError:
        conversations: list[CapturedConversation] = []
    else:
        return _conversations_from(parsed, str(path))

    accepts_empty = False
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            entry = _JSON_LOADS(line)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{path}:{line_no}: invalid JSON — {exc}") from None
        loaded, entry_accepts_empty = _conversations_from(
            entry,
            f"{path}:{line_no}",
        )
        conversations.extend(loaded)
        accepts_empty = accepts_empty or entry_accepts_empty
    return conversations, accepts_empty
