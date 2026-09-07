from __future__ import annotations

from datetime import datetime

from .core.errors import ConfigError
from .corpus_types import (
    ArenaProvenance,
    CapturedConversation,
    CapturedTurn,
    JsonValue,
)


def _required_string(record: dict[str, JsonValue], key: str, source: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{source}: Arena submission needs non-empty '{key}'")
    return value


def _timestamp(record: dict[str, JsonValue], key: str, source: str) -> str:
    value = _required_string(record, key, source)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ConfigError(
            f"{source}: Arena submission '{key}' must be an ISO-8601 timestamp"
        ) from None
    if parsed.tzinfo is None:
        raise ConfigError(
            f"{source}: Arena submission '{key}' must include a timezone"
        )
    return value


def _optional_timestamp(
    record: dict[str, JsonValue],
    key: str,
    source: str,
) -> str | None:
    if key not in record:
        return None
    return _timestamp(record, key, source)


def _messages(value: JsonValue, source: str) -> tuple[CapturedTurn, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{source}: Arena submission messages must be a non-empty list")
    messages: list[CapturedTurn] = []
    expected_role = "user"
    for position, message in enumerate(value):
        if not isinstance(message, dict):
            raise ConfigError(
                f"{source}: Arena message {position} needs string 'role' and 'content'"
            )
        role = message.get("role")
        content = message.get("content")
        if not isinstance(role, str) or not isinstance(content, str):
            raise ConfigError(
                f"{source}: Arena message {position} needs string 'role' and 'content'"
            )
        if role != expected_role:
            raise ConfigError(
                f"{source}: Arena messages must alternate user and assistant, "
                + "starting with user and ending with assistant"
            )
        messages.append(CapturedTurn(role=role, content=content))
        expected_role = "assistant" if expected_role == "user" else "user"
    if messages[-1].role != "assistant":
        raise ConfigError(
            f"{source}: Arena messages must alternate user and assistant, "
            + "starting with user and ending with assistant"
        )
    return tuple(messages)


def _submission(
    value: JsonValue,
    source: str,
    capture_timestamp: str | None,
) -> tuple[CapturedConversation, str]:
    if not isinstance(value, dict):
        raise ConfigError(f"{source}: Arena submission must be a JSON object")
    submission_id = _required_string(value, "_id", source)
    if value.get("grade_status") != "success":
        raise ConfigError(
            f"{source}: Arena submission {submission_id!r} grade_status must be 'success'"
        )
    if value.get("successful") is not True:
        raise ConfigError(
            f"{source}: Arena submission {submission_id!r} successful must be true"
        )
    if not isinstance(value.get("grading"), dict):
        raise ConfigError(
            f"{source}: Arena submission {submission_id!r} needs grading metadata"
        )
    provenance = ArenaProvenance(
        submission_id=submission_id,
        behavior=_required_string(value, "behavior", source),
        model_id=_required_string(value, "model_id", source),
        created_at=_timestamp(value, "created_at", source),
        updated_at=_timestamp(value, "updated_at", source),
        capture_timestamp=capture_timestamp,
    )
    conversation = CapturedConversation(
        messages=_messages(value.get("messages"), source),
        provenance=provenance,
    )
    return conversation, submission_id


def _rows(pages: list[JsonValue], source: str) -> list[JsonValue]:
    rows: list[JsonValue] = []
    for expected_page, page in enumerate(pages):
        if not isinstance(page, dict) or page.get("page") != expected_page:
            raise ConfigError(
                f"{source}: Arena pages must be contiguous and start at page 0"
            )
        expected_more = expected_page < len(pages) - 1
        if page.get("hasMore") is not expected_more:
            raise ConfigError(
                f"{source}: Arena page {expected_page} has inconsistent hasMore"
            )
        submissions = page.get("userSubmissions")
        if not isinstance(submissions, list):
            raise ConfigError(
                f"{source}: Arena page {expected_page} needs userSubmissions"
            )
        rows.extend(submissions)
    return rows


def load_arena_conversations(
    record: dict[str, JsonValue],
    source: str,
) -> list[CapturedConversation]:
    capture_timestamp = _optional_timestamp(record, "capturedAt", source)
    if "pages" in record:
        if record.get("filter") != "accepted":
            raise ConfigError(f"{source}: Arena export filter must be 'accepted'")
        pages = record["pages"]
        if not isinstance(pages, list) or not pages:
            raise ConfigError(f"{source}: Arena export pages must be a non-empty list")
        rows = _rows(pages, source)
        if record.get("reportedTotal") != len(rows):
            raise ConfigError(
                f"{source}: Arena reportedTotal does not match submission count"
            )
    else:
        if record.get("page") != 0 or record.get("hasMore") is not False:
            raise ConfigError(
                f"{source}: Arena page export is incomplete; page must be 0 "
                + "and hasMore must be false"
            )
        submissions = record.get("userSubmissions")
        if not isinstance(submissions, list):
            raise ConfigError(f"{source}: Arena page needs userSubmissions")
        rows = submissions
        if record.get("total") != len(rows):
            raise ConfigError(f"{source}: Arena total does not match submission count")

    conversations: list[CapturedConversation] = []
    submission_ids: set[str] = set()
    for index, row in enumerate(rows):
        conversation, submission_id = _submission(
            row,
            f"{source}: submission {index}",
            capture_timestamp,
        )
        if submission_id in submission_ids:
            raise ConfigError(f"{source}: duplicate submission id {submission_id!r}")
        submission_ids.add(submission_id)
        conversations.append(conversation)
    return conversations
