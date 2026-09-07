from __future__ import annotations

import json
import subprocess

import pytest

dspy = pytest.importorskip("dspy")

from redteam.core.errors import AuthorizationError, ConfigError
from redteam.core.result import Outcome
from redteam.orchestrators import ORCHESTRATORS, execute_run, prepare_run
from redteam.policy.authorization import Authorization
from redteam.targets.base import Target


ATTACK_MODEL = {
    "id": "attacker",
    "plugin": "dspy.stub",
    "options": {},
}


def _config(mock_config, *, profile="vulnerable", **overrides):
    values = {
        "orchestrator": "dspy.redteamer",
        "orchestrator_options": {"attack_model": ATTACK_MODEL, "layers": 2},
        "targets": [
            {"id": "sut", "plugin": "mock.llm", "options": {"profile": profile}}
        ],
        "probes": ["direct.prefix_injection"],
        "transforms": ["identity"],
        "concurrency": 1,
    }
    values.update(overrides)
    return mock_config(**values)


def _corpus(tmp_path):
    path = tmp_path / "corpus.local.jsonl"
    path.write_text(
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
    return path


def test_registration_requires_an_attack_model_with_installable_config():
    assert "dspy.redteamer" in ORCHESTRATORS
    with pytest.raises(ConfigError, match="attack_model") as raised:
        ORCHESTRATORS.create("dspy.redteamer")
    assert '"plugin"' in str(raised.value)


def test_plan_estimate_notes_skips_and_zero_sends(
    mock_config, authorization, tmp_path, monkeypatch
):
    calls = []
    original_send = Target.send

    def recording_send(self, messages, *, tools=()):
        calls.append(self.endpoint)
        return original_send(self, messages, tools=tools)

    monkeypatch.setattr(Target, "send", recording_send)
    config = _config(
        mock_config,
        probes=["direct.prefix_injection", "corpus.custom"],
        transforms=["identity", "encoding.base64"],
    )

    _, plan, _ = prepare_run(
        config,
        authorization,
        max_payloads_per_probe=1,
        corpus_path=str(_corpus(tmp_path)),
    )

    assert calls == []
    assert plan.request_estimate() == 7
    assert len(plan.sendable) == 2
    assert len(plan.skipped) == 2
    assert all("carrier semantics" in item.skip_reason for item in plan.skipped)
    assert any("1 non-generative payload(s)" in note for note in plan.notes)
    assert any("layers×3 requests per attempt" in note for note in plan.notes)


@pytest.mark.parametrize(
    ("profile", "expected_findings"),
    [("vulnerable", 1), ("hardened", 0)],
)
def test_full_loop_preserves_detector_ground_truth(
    mock_config, authorization, profile, expected_findings
):
    orchestrator, plan, ctx = prepare_run(
        _config(mock_config, profile=profile),
        authorization,
        max_payloads_per_probe=1,
    )

    result = execute_run(orchestrator, plan, ctx)

    assert len(result.findings()) == expected_findings
    assert len(result.attempts) == 1
    expected = Outcome.BYPASSED if expected_findings else Outcome.BLOCKED
    assert result.attempts[0].outcome is expected
    assert result.attempts[0].turns == 2


def test_sentinel_drop_is_inconclusive_and_never_reaches_the_sut(
    mock_config, authorization, monkeypatch
):
    calls = []
    original_send = Target.send

    def recording_send(self, messages, *, tools=()):
        calls.append(self.endpoint)
        return original_send(self, messages, tools=tools)

    monkeypatch.setattr(Target, "send", recording_send)
    config = _config(
        mock_config,
        orchestrator_options={
            "attack_model": {
                **ATTACK_MODEL,
                "options": {"drop_sentinel": True},
            },
            "layers": 2,
        },
    )
    orchestrator, plan, ctx = prepare_run(
        config, authorization, max_payloads_per_probe=1
    )

    result = execute_run(orchestrator, plan, ctx)

    assert len(result.attempts) == 1
    assert result.attempts[0].outcome is Outcome.INCONCLUSIVE
    assert any("dropped the sentinel" in v.rationale for v in result.attempts[0].verdicts)
    assert not any(endpoint.startswith("mock:vulnerable") for endpoint in calls)


def test_corpus_sentinel_executes_unreframed_once(
    mock_config, authorization, tmp_path, monkeypatch
):
    calls = []
    original_send = Target.send

    def recording_send(self, messages, *, tools=()):
        calls.append(self.endpoint)
        return original_send(self, messages, tools=tools)

    monkeypatch.setattr(Target, "send", recording_send)
    config = _config(mock_config, probes=["corpus.custom"])
    orchestrator, plan, ctx = prepare_run(
        config,
        authorization,
        corpus_path=str(_corpus(tmp_path)),
        max_payloads_per_probe=1,
    )

    result = execute_run(orchestrator, plan, ctx)

    assert len(result.attempts) == 1
    assert calls == ["mock:vulnerable"]
    assert ctx.budget.spent == 1
    assert result.attempts[0].payload is plan.sendable[0].payload


def test_live_attack_model_is_rejected_by_offline_authorization(mock_config):
    config = _config(
        mock_config,
        orchestrator_options={
            "attack_model": {
                "id": "attacker",
                "plugin": "http.openai_compat",
                "options": {
                    "url": "https://x.example.com/v1/chat/completions",
                    "model": "m",
                    "api_key": "k",
                },
            },
            "layers": 2,
        },
    )

    with pytest.raises(AuthorizationError):
        prepare_run(config, Authorization.offline())


def test_missing_dspy_extra_fails_fresh_process_with_config_error():
    code = (
        "from redteam.orchestrators import ORCHESTRATORS; "
        "ORCHESTRATORS.create('dspy.redteamer', attack_model={"
        "'id':'a','plugin':'http.openai_compat','options':{"
        "'url':'https://x.example.com/v1/chat/completions','model':'m','api_key':'k'}})"
    )

    completed = subprocess.run(
        ["uv", "run", "--no-project", "--isolated", "python", "-c", code],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "ConfigError" in completed.stderr
    assert "ai-redteam[dspy]" in completed.stderr


def test_budget_counts_attack_and_target_roles_together(
    mock_config, authorization, monkeypatch
):
    calls = []
    original_send = Target.send

    def recording_send(self, messages, *, tools=()):
        calls.append(self.endpoint)
        return original_send(self, messages, tools=tools)

    monkeypatch.setattr(Target, "send", recording_send)
    orchestrator, plan, ctx = prepare_run(
        _config(mock_config), authorization, max_payloads_per_probe=1
    )
    ctx.budget.limit = 1

    result = execute_run(orchestrator, plan, ctx)

    assert calls == ["mock:dspy-stub"]
    assert result.attempts == []
    assert any("budget exhausted" in note for note in result.notes)


def test_generated_payload_preserves_carrier_and_is_used_for_judging(
    mock_config, authorization, monkeypatch
):
    config = _config(mock_config, probes=["indirect.tool_output"])
    orchestrator, plan, ctx = prepare_run(
        config, authorization, max_payloads_per_probe=1
    )
    original_payload = plan.sendable[0].payload
    judged = []
    original_judge = orchestrator.judge

    def recording_judge(payload, response, conversation, run_ctx):
        judged.append(payload)
        return original_judge(payload, response, conversation, run_ctx)

    monkeypatch.setattr(orchestrator, "judge", recording_judge)

    result = execute_run(orchestrator, plan, ctx)

    attempt = result.attempts[0]
    changed = [
        index
        for index, (before, after) in enumerate(
            zip(original_payload.messages, attempt.payload.messages, strict=True)
        )
        if before != after
    ]
    assert changed == [len(original_payload.messages) - 1]
    attack_index = changed[0]
    assert attempt.payload.messages[attack_index].content != original_payload.messages[
        attack_index
    ].content
    assert attempt.payload.messages[attack_index].role == "tool"
    assert attempt.payload.messages[attack_index].name == original_payload.messages[
        attack_index
    ].name
    assert attempt.payload.messages[attack_index].trusted is False
    assert attempt.payload.messages[:attack_index] == original_payload.messages[:attack_index]
    assert attempt.payload.attack_text() == attempt.payload.messages[attack_index].content
    assert judged == [attempt.payload]
