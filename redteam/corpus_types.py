from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias, TypedDict

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


class CorpusMessage(TypedDict):
    role: str
    content: str


class ArenaMetadata(TypedDict, total=False):
    source_type: str
    arena_submission_id: str
    arena_behavior: str
    arena_model_id: str
    arena_created_at: str
    arena_updated_at: str
    arena_grade_status: str
    arena_successful: bool
    arena_capture_timestamp: str


@dataclass(frozen=True, slots=True)
class CapturedTurn:
    role: str
    content: str

    def as_message(self) -> CorpusMessage:
        return {"role": self.role, "content": self.content}


@dataclass(frozen=True, slots=True)
class ArenaProvenance:
    submission_id: str
    behavior: str
    model_id: str
    created_at: str
    updated_at: str
    capture_timestamp: str | None

    def as_metadata(self) -> ArenaMetadata:
        metadata = ArenaMetadata(
            source_type="grayswan_arena_accepted_export",
            arena_submission_id=self.submission_id,
            arena_behavior=self.behavior,
            arena_model_id=self.model_id,
            arena_created_at=self.created_at,
            arena_updated_at=self.updated_at,
            arena_grade_status="success",
            arena_successful=True,
        )
        if self.capture_timestamp is not None:
            metadata["arena_capture_timestamp"] = self.capture_timestamp
        return metadata


@dataclass(frozen=True, slots=True)
class CapturedConversation:
    messages: tuple[CapturedTurn, ...]
    provenance: ArenaProvenance | None = None

    def as_messages(self) -> list[CorpusMessage]:
        return [message.as_message() for message in self.messages]

    def metadata(self) -> ArenaMetadata:
        if self.provenance is None:
            return ArenaMetadata()
        return self.provenance.as_metadata()
