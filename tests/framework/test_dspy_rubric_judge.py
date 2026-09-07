"""Unit tests for the DSPy rubric judge's pure logic (no LLM calls)."""

import json

import pytest

from redteam.dspy.rubric_judge import (
    build_dataset_record,
    parse_scores,
    rubric_agreement,
    render_transcript,
)


def test_parse_scores_handles_valid_json_and_case_insensitive_names():
    parsed = parse_scores(
        '{"Precursors": 8, " realism ": 7, "Extra": 3}',
        ["Precursors", "Realism"],
    )
    assert parsed == {"Precursors": 8, "Realism": 7}


def test_parse_scores_returns_none_for_garbage_and_missing():
    parsed = parse_scores("not json at all", ["alpha", "beta"])
    assert parsed == {"alpha": None, "beta": None}
    parsed = parse_scores('{"alpha": "high", "beta": null}', ["alpha", "beta"])
    assert parsed == {"alpha": None, "beta": None}


def test_parse_scores_accepts_nested_score_dicts():
    parsed = parse_scores(
        '{"alpha": {"score": 9, "why": "x"}}',
        ["alpha"],
    )
    assert parsed == {"alpha": 9}


def test_rubric_agreement_rewards_exact_and_partial_matches():
    example = {
        "criteria_labels": {"alpha": 9, "beta": 4},
        "is_break": True,
    }
    prediction = {
        "scores_json": json.dumps({"alpha": 9, "beta": 3}),
        "overall_break": True,
    }
    # alpha exact (1.0) + beta off-by-one (0.5) -> score component 0.75;
    # break agrees -> 0.75 * 0.75 + 0.25 * 1.0
    assert rubric_agreement(example, prediction) == pytest.approx(
        0.75 * 0.75 + 0.25
    )


def test_rubric_agreement_penalizes_wrong_break():
    example = {
        "criteria_labels": {"alpha": 9},
        "is_break": True,
    }
    prediction = {
        "scores_json": json.dumps({"alpha": 9}),
        "overall_break": False,
    }
    assert rubric_agreement(example, prediction) == pytest.approx(0.75)


def test_rubric_agreement_zero_on_total_disagreement():
    example = {
        "criteria_labels": {"alpha": 9, "beta": 9},
        "is_break": True,
    }
    prediction = {
        "scores_json": json.dumps({"alpha": 0, "beta": 1}),
        "overall_break": False,
    }
    assert rubric_agreement(example, prediction) == 0.0


def test_render_transcript_joins_roles():
    transcript = render_transcript([
        {"role": "user", "content": "hello"},
        {"role": "assistant", "content": "no"},
    ])
    assert transcript == "USER: hello\n\nASSISTANT: no"


def test_build_dataset_record_joins_graph_rubric_with_platform_labels():
    record = {
        "_id": "api-1",
        "behavior": "demo-a",
        "chat_id": "chat-1",
        "model_id": "m1",
        "created_at": "2026-09-05T00:00:00Z",
        "updated_at": "2026-09-05T01:00:00Z",
        "grade_status": "pass",
        "successful": True,
        "energy_deducted_from_regen": 4,
        "energy_deducted_from_bank": 6,
        "grading": {
            "is_break": True,
            "criteria": {
                "c0": {"criteria_name": "Depth", "score": 8, "analysis": "deep"},
                "c1": {"criteria_name": "Realism", "score": 7, "analysis": None},
            },
        },
        "messages": [{"role": "user", "content": "go"}],
    }
    behavior = {
        "slug": "demo-a",
        "name": "Demo A",
        "objective": "Achieve the thing",
        "criteria": [
            {"name": "Depth", "description": "Goes deep"},
            {"name": "Realism", "description": "Feels real"},
            {"name": "Bonus", "description": "Not graded here"},
        ],
    }
    entry = build_dataset_record(record, behavior, "CatOne", "demo-alias-one")
    # Graded criteria carry platform scores; ungraded graph criteria (Bonus)
    # appear as None so the metric can skip them honestly.
    assert entry["criteria_labels"] == {"Depth": 8, "Realism": 7, "Bonus": None}
    assert entry["criteria_analyses"] == {"Depth": "deep"}
    assert entry["criteria_analyses"] == {"Depth": "deep"}
    by_name = {c["name"]: c for c in entry["criteria"]}
    assert by_name["Depth"]["description"] == "Goes deep"
    assert by_name["Depth"]["platform_score"] == 8
    assert by_name["Realism"]["platform_score"] == 7
    assert entry["is_break"] is True
    assert entry["energy_spent"] == 10
    assert entry["transcript"] == "USER: go"
    assert entry["model_alias"] == "demo-alias-one"
