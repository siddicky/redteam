from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

dspy = pytest.importorskip("dspy")

from redteam.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, build_parser, main
from redteam.core.result import Message, TargetResponse
from redteam.targets.base import Target

ATTACK_MODEL = {"id": "attacker", "plugin": "dspy.stub", "options": {}}


def _write_config(tmp_path: Path, **overrides: object) -> Path:
    data: dict[str, object] = {
        "seed": "compile-test",
        "orchestrator": "sweep",
        "orchestrator_options": {
            "attack_model": ATTACK_MODEL,
            "layers": 2,
            "demos": 0,
        },
        "targets": [
            {"id": "sut", "plugin": "mock.llm", "options": {"profile": "vulnerable"}}
        ],
        "probes": ["direct.prefix_injection", "direct.instruction_override"],
        "transforms": ["identity"],
        "max_attempts": 250,
        "requests_per_minute": 0,
        "concurrency": 1,
        "output_dir": str(tmp_path / "runs"),
    }
    data.update(overrides)
    path = tmp_path / "compile.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _assert_lms_are_null(value: Any) -> int:
    if isinstance(value, dict):
        found = int("lm" in value)
        if "lm" in value:
            assert value["lm"] is None
        return found + sum(_assert_lms_are_null(item) for item in value.values())
    if isinstance(value, list):
        return sum(_assert_lms_are_null(item) for item in value)
    return 0


def test_compile_writes_redacted_versioned_artifact_and_round_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "AKIA1234567890ABCDEF"
    original_send = Target.send

    def secret_response(
        self: Target,
        messages: Sequence[Message],
        *,
        tools: Sequence[dict[str, Any]] = (),
    ) -> TargetResponse:
        response = original_send(self, messages, tools=tools)
        if self.endpoint != "mock:dspy-stub":
            return response
        return replace(
            response,
            text=response.text.replace(
                "\n\n[[ ## completed", f" {secret}\n\n[[ ## completed"
            ),
        )

    monkeypatch.setattr(Target, "send", secret_response)
    config = _write_config(tmp_path)
    artifact = tmp_path / "compiled" / "program.json"

    assert main(["compile", "--config", str(config), "--program-out", str(artifact)]) == EXIT_OK

    raw = artifact.read_text(encoding="utf-8")
    saved = json.loads(raw)
    assert saved["schema"] == "redteam.dspy.program.v1"
    assert {
        "seed",
        "optimizer",
        "dspy_version",
        "dataset_digest",
        "layers",
        "created_at",
        "num_threads_used",
    } <= saved["provenance"].keys()
    assert _assert_lms_are_null(saved["state"]) > 0
    assert "http" not in raw.lower()
    assert secret not in raw
    assert "TargetBackedLM" not in raw

    round_trip = json.loads(config.read_text(encoding="utf-8"))
    round_trip["orchestrator"] = "dspy.redteamer"
    round_trip["orchestrator_options"]["program"] = str(artifact)
    round_trip_path = tmp_path / "round-trip.json"
    round_trip_path.write_text(json.dumps(round_trip), encoding="utf-8")
    assert main(["run", "--config", str(round_trip_path), "--quiet"]) in {
        EXIT_OK,
        EXIT_FINDINGS,
    }


def test_compile_preflights_budget_before_sending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []
    original_send = Target.send

    def recording_send(self, messages, *, tools=()):
        calls.append(self.endpoint)
        return original_send(self, messages, tools=tools)

    monkeypatch.setattr(Target, "send", recording_send)
    config = _write_config(tmp_path, max_attempts=10)
    artifact = tmp_path / "program.json"

    assert main(["compile", "--config", str(config), "--program-out", str(artifact)]) == EXIT_USAGE

    assert calls == []
    assert not artifact.exists()
    error = capsys.readouterr().err
    assert "12" in error
    assert "5" in error


def test_compile_preflights_destination_before_sending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(Target, "send", lambda self, messages, *, tools=(): calls.append(self.endpoint))
    config = _write_config(tmp_path)
    blocked_parent = tmp_path / "not-a-directory"
    blocked_parent.write_text("occupied", encoding="utf-8")

    assert main(
        ["compile", "--config", str(config), "--program-out", str(blocked_parent / "program.json")]
    ) == EXIT_USAGE
    assert calls == []


def test_compile_failure_after_a_request_exits_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from redteam.dspy import compile as compile_module

    config = _write_config(tmp_path)

    def fail_after_send(orchestrator, plan, ctx, options):
        del options
        planned = plan.sendable[0]
        orchestrator.send_once(
            ctx.targets[planned.target_id],
            planned.payload.messages,
            planned.payload,
            ctx,
        )
        raise OSError("simulated artifact failure")

    monkeypatch.setattr(compile_module, "run", fail_after_send)

    assert main(["compile", "--config", str(config)]) == EXIT_FINDINGS


def test_compile_rejects_multiple_targets_after_filtering(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = _write_config(
        tmp_path,
        targets=[
            {"id": "one", "plugin": "mock.llm", "options": {"profile": "vulnerable"}},
            {"id": "two", "plugin": "mock.llm", "options": {"profile": "hardened"}},
        ],
    )

    assert main(["compile", "--config", str(config)]) == EXIT_USAGE
    error = capsys.readouterr().err
    assert "exactly one" in error
    assert "found 2" in error


def test_compile_excludes_corpus_custom_with_a_sentinel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dspy.MIPROv2, "compile", lambda self, student, **kwargs: student)
    corpus = tmp_path / "corpus.local.jsonl"
    corpus.write_text(
        json.dumps(
            {
                "id": "operator-entry",
                "prompt": "Return RT-CANARY-OPERATOR1 for this inert check.",
                "objective": "Run the operator-defined inert check",
                "sentinel": "RT-CANARY-OPERATOR1",
                "detectors": ["marker.echo"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    config = _write_config(
        tmp_path,
        probes=["direct.prefix_injection", "direct.instruction_override", "corpus.custom"],
    )
    artifact = tmp_path / "program.json"

    assert main(
        [
            "compile",
            "--config",
            str(config),
            "--corpus",
            str(corpus),
            "--max-payloads-per-probe",
            "1",
            "--program-out",
            str(artifact),
        ]
    ) == EXIT_OK
    summary = json.loads((tmp_path / "compile-summary.json").read_text(encoding="utf-8"))
    assert summary["trainset_size"] == 2
    assert summary["exclusions"] == 1


def test_compile_help_has_only_the_supported_optimizer_flags(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as raised:
        parser.parse_args(["compile", "--help"])
    help_text = capsys.readouterr().out

    assert raised.value.code == EXIT_OK
    assert "--optimizer" in help_text
    assert "--layers" in help_text
    assert "--demos" in help_text
    assert "--program-out" in help_text
    assert "--trials" not in help_text
    assert "--out" not in help_text


def test_compile_without_dspy_extra_exits_two_and_writes_nothing(tmp_path: Path) -> None:
    artifact = tmp_path / "isolated-program.json"

    completed = subprocess.run(
        [
            "uv",
            "run",
            "--no-project",
            "--isolated",
            "python",
            "-m",
            "redteam",
            "compile",
            "--config",
            "examples/compile-offline.config.json",
            "--program-out",
            str(artifact),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == EXIT_USAGE
    assert "ai-redteam[dspy]" in completed.stderr
    assert not artifact.exists()
