from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from redteam.cli import EXIT_OK, main
from redteam.corpus_types import JsonValue

_JSON_LOADS: Callable[[str], JsonValue] = json.loads


def _accepted_submission(submission_id: str = "submission-1") -> dict[str, JsonValue]:
    return {
        "_id": submission_id,
        "behavior": "inert-behavior",
        "chat_id": "private-chat-id",
        "grade_status": "success",
        "grading": {"is_break": True, "criteria": []},
        "messages": [
            {"role": "user", "content": "<inert user turn>", "id": "message-1"},
            {
                "role": "assistant",
                "content": "<inert assistant reply>",
                "id": "message-2",
            },
        ],
        "model_id": "model-1",
        "successful": True,
        "created_at": "2026-08-31T05:41:22.508Z",
        "updated_at": "2026-08-31T05:41:39.591Z",
        "user_id": "private-user-id",
        "classifier_logs": {"private": True},
        "history": {"private": True},
        "system_prompt": {"private": True},
    }


def _arena_export(
    *submissions: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    return {
        "capturedAt": "2026-08-31T16:30:00.000Z",
        "source": "/private/arena/request/url",
        "filter": "accepted",
        "reportedTotal": len(submissions),
        "pages": [
            {
                "page": 0,
                "hasMore": False,
                "userSubmissions": list(submissions),
            }
        ],
    }


def _write_json(path: Path, value: dict[str, JsonValue]) -> str:
    _ = path.write_text(json.dumps(value), encoding="utf-8")
    return str(path)


def _invalid_arena_exports() -> list[tuple[str, dict[str, JsonValue], str]]:
    wrong_filter = _arena_export(_accepted_submission())
    wrong_filter["filter"] = "rejected"

    unsuccessful = _accepted_submission()
    unsuccessful["successful"] = False

    wrong_total = _arena_export(_accepted_submission())
    wrong_total["reportedTotal"] = 2

    incomplete = _arena_export(_accepted_submission())
    incomplete["pages"] = [
        {
            "page": 0,
            "hasMore": True,
            "userSubmissions": [_accepted_submission()],
        }
    ]

    duplicate = _arena_export(
        _accepted_submission("duplicate"),
        _accepted_submission("duplicate"),
    )

    malformed_messages = _accepted_submission()
    malformed_messages["messages"] = [
        {"role": "assistant", "content": "<inert reply>"},
        {"role": "user", "content": "<inert turn>"},
    ]

    invalid_capture_timestamp = _arena_export(_accepted_submission())
    invalid_capture_timestamp["capturedAt"] = "not-a-timestamp"

    return [
        ("filter-not-accepted", wrong_filter, "filter must be 'accepted'"),
        ("unsuccessful-row", _arena_export(unsuccessful), "successful must be true"),
        ("reported-total-mismatch", wrong_total, "reportedTotal"),
        ("incomplete-pagination", incomplete, "hasMore"),
        ("duplicate-submission-id", duplicate, "duplicate submission id"),
        (
            "invalid-message-order",
            _arena_export(malformed_messages),
            "alternate user and assistant",
        ),
        (
            "invalid-capture-timestamp",
            invalid_capture_timestamp,
            "capturedAt",
        ),
    ]


INVALID_ARENA_EXPORTS = _invalid_arena_exports()


def test_corpus_import_accepts_complete_arena_export_with_safe_provenance(
    tmp_path: Path,
) -> None:
    source = _write_json(tmp_path / "arena.local.json", _arena_export(_accepted_submission()))
    out = tmp_path / "corpus.local.jsonl"

    assert main(["corpus", "import", source, "--out", str(out)]) == EXIT_OK

    entry = _JSON_LOADS(out.read_text(encoding="utf-8"))
    assert isinstance(entry, dict)
    assert entry["messages"] == [
        {"role": "user", "content": "<inert user turn>"},
        {"role": "assistant", "content": "<inert assistant reply>"},
    ]
    assert entry["metadata"] == {
        "source_type": "grayswan_arena_accepted_export",
        "arena_submission_id": "submission-1",
        "arena_behavior": "inert-behavior",
        "arena_model_id": "model-1",
        "arena_created_at": "2026-08-31T05:41:22.508Z",
        "arena_updated_at": "2026-08-31T05:41:39.591Z",
        "arena_grade_status": "success",
        "arena_successful": True,
        "arena_capture_timestamp": "2026-08-31T16:30:00.000Z",
    }
    serialized = json.dumps(entry)
    for private_value in (
        "private-chat-id",
        "private-user-id",
        "/private/arena/request/url",
        "classifier_logs",
        "system_prompt",
    ):
        assert private_value not in serialized


def test_corpus_import_accepts_a_complete_single_arena_page(tmp_path: Path) -> None:
    source = _write_json(
        tmp_path / "arena-page.local.json",
        {
            "userSubmissions": [_accepted_submission()],
            "total": 1,
            "unfilteredTotal": 2,
            "page": 0,
            "hasMore": False,
        },
    )
    out = tmp_path / "corpus.local.jsonl"

    assert main(["corpus", "import", source, "--out", str(out)]) == EXIT_OK
    assert len(out.read_text(encoding="utf-8").splitlines()) == 1


def test_corpus_import_accepts_an_empty_complete_arena_page(tmp_path: Path) -> None:
    source = _write_json(
        tmp_path / "empty-arena-page.local.json",
        {
            "userSubmissions": [],
            "total": 0,
            "unfilteredTotal": 2,
            "page": 0,
            "hasMore": False,
        },
    )
    out = tmp_path / "corpus.local.jsonl"

    assert main(["corpus", "import", source, "--out", str(out)]) == EXIT_OK
    assert out.read_text(encoding="utf-8") == ""


@pytest.mark.parametrize(
    ("arena_export", "expected_error"),
    [(value, expected) for _, value, expected in INVALID_ARENA_EXPORTS],
    ids=[name for name, _, _ in INVALID_ARENA_EXPORTS],
)
def test_corpus_import_rejects_invalid_arena_export_without_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arena_export: dict[str, JsonValue],
    expected_error: str,
) -> None:
    source = _write_json(tmp_path / "arena.local.json", arena_export)
    out = tmp_path / "corpus.local.jsonl"

    assert main(["corpus", "import", source, "--out", str(out)]) != EXIT_OK
    assert not out.exists()
    assert expected_error in capsys.readouterr().err


def test_corpus_import_scans_and_redacts_arena_provenance(tmp_path: Path) -> None:
    submission = _accepted_submission()
    submission["behavior"] = "owner@example.org"
    source = _write_json(tmp_path / "arena.local.json", _arena_export(submission))
    blocked_out = tmp_path / "blocked.local.jsonl"

    assert main(["corpus", "import", source, "--out", str(blocked_out)]) != EXIT_OK
    assert not blocked_out.exists()

    redacted_out = tmp_path / "redacted.local.jsonl"
    assert (
        main(
            [
                "corpus",
                "import",
                source,
                "--out",
                str(redacted_out),
                "--redact",
            ]
        )
        == EXIT_OK
    )
    entry = _JSON_LOADS(redacted_out.read_text(encoding="utf-8"))
    assert isinstance(entry, dict)
    metadata = entry["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["arena_behavior"] == "[REDACTED:email]"
    assert "owner@example.org" not in redacted_out.read_text(encoding="utf-8")
