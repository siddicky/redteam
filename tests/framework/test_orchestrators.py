"""Orchestration: planning, the authorization interlock, and the three strategies.

The interlock tests are the ones that must never be deleted. ``prepare_run`` is the
only place a target gets instantiated and a request becomes possible, so if the gate
can be reached without passing, nothing else in :mod:`redteam.policy` matters.
"""

from __future__ import annotations

import pytest

from redteam.core.config import TargetConfig
from redteam.core.errors import AuthorizationError, ConfigError, PolicyViolation
from redteam.core.result import Outcome, Risk, TargetResponse
from redteam.orchestrators import ORCHESTRATORS, execute_run, prepare_run
from redteam.orchestrators.strategies import SweepOrchestrator
from redteam.orchestrators.strategies import DEFAULT_ESCALATION
from redteam.targets import TARGETS
from redteam.targets.base import Target


@TARGETS.register("test.auxiliary", summary="Test auxiliary target")
class AuxiliaryStubTarget(Target):
    closed = False

    def __init__(self, *, url: str = "mock:aux-stub", **options):
        super().__init__(**options)
        self._url = url
        type(self).closed = False

    @property
    def endpoint(self) -> str:
        return self._url

    def _send(self, messages, tools) -> TargetResponse:
        return TargetResponse(text="auxiliary")

    def close(self) -> None:
        type(self).closed = True


@ORCHESTRATORS.register("test.auxiliary", summary="Test auxiliary orchestrator")
class AuxiliaryOrchestrator(SweepOrchestrator):
    def auxiliary_targets(self) -> dict[str, TargetConfig]:
        return {
            "attack": TargetConfig.from_dict(
                self.options.get(
                    "attack_model",
                    {"id": "aux", "plugin": "test.auxiliary", "options": {}},
                )
            )
        }


def _run(config, authorization, **kwargs):
    orchestrator, plan, ctx = prepare_run(config, authorization, **kwargs)
    return execute_run(orchestrator, plan, ctx), plan, ctx


def _orchestrator_options(orchestrator_id: str) -> dict:
    """Options that let option-requiring orchestrators participate in registry-wide tests."""
    if orchestrator_id == "dspy.redteamer":
        return {
            "attack_model": {
                "id": "attacker",
                "plugin": "dspy.stub",
                "options": {},
            },
            "layers": 1,
        }
    return {}


# --------------------------------------------------------------------------- #
# The authorization interlock
# --------------------------------------------------------------------------- #
def test_prepare_run_authorizes_every_target(mock_config, authorization_record):
    from redteam.policy.authorization import Authorization

    authorization_record["scope"]["targets"] = ["replay:*"]  # mock: no longer in scope
    authorization = Authorization.from_dict(authorization_record)
    with pytest.raises(AuthorizationError, match="not in the authorized scope"):
        prepare_run(mock_config(), authorization)


def test_prepare_run_refuses_a_denylisted_target(authorization_record, mock_config):
    from redteam.policy.authorization import Authorization

    authorization_record["scope"]["targets"].append("https://blocked.example.com/*")
    authorization_record["scope"]["deny"] = ["blocked.example.com"]
    config = mock_config(
        targets=[
            {
                "id": "blocked",
                "plugin": "http.openai_compat",
                "options": {"url": "https://blocked.example.com/api", "model": "m"},
            }
        ]
    )
    with pytest.raises(PolicyViolation, match="denied"):
        prepare_run(config, Authorization.from_dict(authorization_record))


def test_prepare_run_refuses_an_expired_record(mock_config, expired_authorization):
    with pytest.raises(AuthorizationError, match="expired"):
        prepare_run(mock_config(), expired_authorization)


def test_prepare_run_requires_at_least_one_target(mock_config, authorization):
    with pytest.raises(ConfigError, match="no targets"):
        prepare_run(mock_config(targets=[]), authorization)


def test_prepare_run_authorizes_and_exposes_auxiliary_target(mock_config, authorization):
    config = mock_config(orchestrator="test.auxiliary")
    _, _, ctx = prepare_run(config, authorization)
    assert ctx.auxiliary_targets["attack"].endpoint == "mock:aux-stub"
    assert any("auxiliary endpoint authorized (attack): mock:aux-stub" in note for note in ctx.notes)


def test_prepare_run_rejects_unauthorized_live_auxiliary(mock_config):
    from redteam.policy.authorization import Authorization

    config = mock_config(
        orchestrator="test.auxiliary",
        orchestrator_options={
            "attack_model": {
                "id": "aux",
                "plugin": "test.auxiliary",
                "options": {"url": "https://fake-aux.example.invalid/model"},
            }
        },
    )
    with pytest.raises(AuthorizationError):
        prepare_run(config, Authorization.offline())


def test_live_auxiliary_keeps_rate_limiter_enabled(mock_config, authorization_record):
    from redteam.core.ratelimit import NullRateLimiter, RateLimiter
    from redteam.policy.authorization import Authorization

    endpoint = "https://fake-aux.example.invalid/model"
    authorization_record["scope"]["targets"].append(endpoint)
    config = mock_config(
        orchestrator="test.auxiliary",
        orchestrator_options={
            "attack_model": {
                "id": "aux",
                "plugin": "test.auxiliary",
                "options": {"url": endpoint},
            }
        },
    )
    _, _, ctx = prepare_run(config, Authorization.from_dict(authorization_record))
    assert isinstance(ctx.limiter, RateLimiter)
    assert not isinstance(ctx.limiter, NullRateLimiter)


def test_execute_run_closes_auxiliary_targets(mock_config, authorization):
    AuxiliaryStubTarget.closed = False
    orchestrator, plan, ctx = prepare_run(
        mock_config(orchestrator="test.auxiliary"), authorization
    )
    execute_run(orchestrator, plan, ctx)
    assert AuxiliaryStubTarget.closed


def test_run_result_lists_only_system_targets(mock_config, authorization):
    result, _, ctx = _run(mock_config(orchestrator="test.auxiliary"), authorization)
    assert result.targets == list(ctx.targets)
    assert "attack" not in result.targets


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #
def test_plan_is_deterministic(mock_config, authorization):
    first = prepare_run(mock_config(), authorization)[1]
    second = prepare_run(mock_config(), authorization)[1]
    assert first.to_dict() == second.to_dict()


def test_plan_covers_the_cross_product(mock_config, authorization):
    config = mock_config(
        probes=["direct.instruction_override"],
        transforms=["identity", "encoding.base64"],
        targets=[
            {"id": "a", "plugin": "mock.llm", "options": {"profile": "balanced"}},
            {"id": "b", "plugin": "mock.llm", "options": {"profile": "hardened"}},
        ],
    )
    plan = prepare_run(config, authorization)[1]
    # 5 payloads x 2 transforms x 2 targets
    assert len(plan.sendable) == 20
    assert set(plan.targets) == {"a", "b"}


def test_plan_records_a_request_estimate_that_accounts_for_multi_turn(
    mock_config, authorization
):
    """A crescendo run costs one request per rung; a naive count understates it 4x."""
    config = mock_config(orchestrator="crescendo", probes=["multiturn.crescendo"])
    plan = prepare_run(config, authorization)[1]
    assert plan.request_estimate() > len(plan.sendable)


def test_plan_skips_a_multiturn_probe_under_a_single_turn_orchestrator(
    mock_config, authorization
):
    """Recorded as a skip, not a pass: an unrun probe is not evidence of safety."""
    config = mock_config(orchestrator="sweep", probes=["multiturn.crescendo"])
    plan = prepare_run(config, authorization)[1]
    assert not plan.sendable
    assert plan.skipped
    assert "crescendo orchestrator" in plan.skipped[0].skip_reason


def test_plan_skips_a_system_prompt_probe_against_a_target_that_drops_it(
    mock_config, authorization
):
    config = mock_config(
        probes=["leak.system_prompt"],
        targets=[
            {
                "id": "fixed",
                "plugin": "mock.llm",
                "options": {"profile": "balanced", "system_prompt_mode": "drop"},
            }
        ],
    )
    plan = prepare_run(config, authorization)[1]
    assert not plan.sendable
    assert "system_prompt_mode is 'drop'" in plan.skipped[0].skip_reason


def test_plan_truncates_to_the_attempt_ceiling_and_says_so(mock_config, authorization):
    """Silent truncation would read as full coverage. It must be loud."""
    config = mock_config(probes=["indirect"], max_attempts=5)
    plan = prepare_run(config, authorization)[1]
    assert len(plan.sendable) == 5
    assert plan.truncated
    assert any("NOT covered" in note for note in plan.notes)


def test_authorization_ceilings_override_the_config(mock_config, authorization_record):
    from redteam.policy.authorization import Authorization

    authorization_record["scope"]["max_attempts"] = 3
    authorization_record["scope"]["max_requests_per_minute"] = 5
    authorization_record["scope"]["max_concurrency"] = 1
    authorization = Authorization.from_dict(authorization_record)
    config = mock_config(
        probes=["indirect.document"], max_attempts=100, requests_per_minute=600, concurrency=8
    )
    _, plan, ctx = prepare_run(config, authorization)
    assert len(plan.sendable) == 3
    assert ctx.budget.limit == 3
    assert any("lowered" in note for note in ctx.notes)


def test_min_risk_filters_the_probe_set(mock_config, authorization):
    config = mock_config(probes=None, min_risk="critical")
    _, plan, _ = prepare_run(config, authorization)
    assert plan.probes
    for probe_id in plan.probes:
        from redteam.probes import build_probe

        assert build_probe(probe_id).risk is Risk.CRITICAL


def test_min_risk_that_matches_nothing_is_an_error(mock_config, authorization):
    config = mock_config(probes=["direct.prefix_injection"], min_risk="critical")
    with pytest.raises(ConfigError, match="no probes remain"):
        prepare_run(config, authorization)


def test_offline_targets_skip_rate_limiting(mock_config, authorization):
    """Throttling the simulator would only make the demo too slow to run."""
    from redteam.core.ratelimit import NullRateLimiter

    _, _, ctx = prepare_run(mock_config(requests_per_minute=1), authorization)
    assert isinstance(ctx.limiter, NullRateLimiter)
    assert any("offline" in note for note in ctx.notes)


# --------------------------------------------------------------------------- #
# Sweep
# --------------------------------------------------------------------------- #
def test_sweep_produces_one_result_per_planned_attempt(mock_config, authorization):
    result, plan, _ = _run(mock_config(probes=["indirect.document"]), authorization)
    assert len(result.attempts) == len(plan.attempts)


def test_sweep_finds_the_bypasses_the_simulator_is_designed_to_have(
    mock_config, authorization
):
    """Ground truth: the balanced profile trusts retrieved content, so every
    indirect-document family should get through."""
    result, _, _ = _run(mock_config(probes=["indirect.document"]), authorization)
    findings = result.findings()
    assert len(findings) == 7  # one per playbook family
    assert all(f.payload.carrier == "document" for f in findings)


def test_sweep_finds_nothing_against_a_hardened_target(mock_config, authorization):
    """The other half of the ground truth: detectors must not simply always fire."""
    config = mock_config(
        probes=["indirect", "direct", "agency", "exfil"],
        targets=[{"id": "hard", "plugin": "mock.llm", "options": {"profile": "hardened"}}],
    )
    result, _, _ = _run(config, authorization)
    assert result.findings() == []
    assert result.ok(fail_on=None)
    # And every attempt reached a verdict, so the pass is real coverage.
    assert all(a.outcome is Outcome.BLOCKED for a in result.attempts)


def test_sweep_records_authorization_provenance_in_the_result(mock_config, authorization):
    result, _, _ = _run(mock_config(), authorization)
    assert result.authorization["engagement"] == "test engagement"
    assert result.authorization["reference"] == "TEST-1"


def test_sweep_is_reproducible(mock_config, authorization):
    def signature(result):
        return [
            (a.target, a.payload.probe, a.payload.payload_id, a.outcome.value)
            for a in result.attempts
        ]

    first, _, _ = _run(mock_config(probes=["indirect.document"]), authorization)
    second, _, _ = _run(mock_config(probes=["indirect.document"]), authorization)
    assert signature(first) == signature(second)


def test_concurrency_does_not_change_the_outcome(mock_config, authorization):
    serial, _, _ = _run(mock_config(probes=["indirect"], concurrency=1), authorization)
    parallel, _, _ = _run(mock_config(probes=["indirect"], concurrency=4), authorization)
    assert len(serial.findings()) == len(parallel.findings())


def test_budget_exhaustion_stops_the_run_and_is_noted(mock_config, authorization):
    from redteam.core.ratelimit import Budget

    orchestrator, plan, ctx = prepare_run(mock_config(probes=["indirect"]), authorization)
    ctx.budget = Budget(limit=3)
    result = execute_run(orchestrator, plan, ctx)
    assert len(result.attempts) <= 3
    assert any("budget exhausted" in note for note in result.notes)


def test_skipped_attempts_appear_in_the_result(mock_config, authorization):
    config = mock_config(orchestrator="sweep", probes=["multiturn.crescendo"])
    result, _, _ = _run(config, authorization)
    assert result.attempts
    assert all(a.outcome is Outcome.SKIPPED for a in result.attempts)
    assert result.ok(fail_on=None)  # a skip is not a finding
    from redteam.scoring import summarize

    # ...but it is also not a pass: it contributes nothing to the rate.
    assert summarize(result).scored == 0
    assert summarize(result).coverage_warning


# --------------------------------------------------------------------------- #
# Crescendo
# --------------------------------------------------------------------------- #
def test_crescendo_walks_the_ladder_and_records_the_rung(mock_config, authorization):
    config = mock_config(
        orchestrator="crescendo",
        probes=["multiturn.crescendo"],
        targets=[{"id": "chat", "plugin": "mock.llm", "options": {"profile": "naive_chat"}}],
    )
    result, _, _ = _run(config, authorization)
    findings = result.findings()
    assert findings
    for finding in findings:
        assert finding.turns > 1, "a bypass on turn one is not an escalation"
        assert finding.payload.metadata["bypassed_on_turn"] == finding.turns


def test_crescendo_stops_at_the_first_bypass(mock_config, authorization):
    """Continuing past a bypass spends requests to learn nothing."""
    config = mock_config(
        orchestrator="crescendo",
        probes=["multiturn.crescendo"],
        targets=[{"id": "chat", "plugin": "mock.llm", "options": {"profile": "naive_chat"}}],
    )
    result, _, _ = _run(config, authorization)
    for finding in result.findings():
        assert finding.turns <= finding.payload.metadata["ladder_length"]


def test_crescendo_against_a_hardened_target_sends_the_whole_ladder(
    mock_config, authorization
):
    config = mock_config(
        orchestrator="crescendo",
        probes=["multiturn.crescendo"],
        targets=[{"id": "hard", "plugin": "mock.llm", "options": {"profile": "hardened"}}],
    )
    result, _, _ = _run(config, authorization)
    assert result.findings() == []
    for attempt in result.attempts:
        assert attempt.turns == attempt.payload.metadata["ladder_length"]


def test_crescendo_max_turns_bounds_the_request_cost(mock_config, authorization):
    config = mock_config(
        orchestrator="crescendo",
        probes=["multiturn.crescendo"],
        orchestrator_options={"max_turns": 2},
        targets=[{"id": "hard", "plugin": "mock.llm", "options": {"profile": "hardened"}}],
    )
    result, _, _ = _run(config, authorization)
    assert all(a.turns <= 2 for a in result.attempts)


# --------------------------------------------------------------------------- #
# Adaptive
# --------------------------------------------------------------------------- #
def test_adaptive_escalates_a_blocked_baseline_and_names_the_boundary(
    mock_config, authorization
):
    """The finding is not just the bypass — it is that the plain payload was blocked
    and the transformed one was not, which locates the defect in the input filter."""
    config = mock_config(
        orchestrator="adaptive",
        probes=["direct.instruction_override"],
        targets=[{"id": "filtered", "plugin": "mock.llm", "options": {"profile": "balanced"}}],
    )
    result, _, ctx = _run(config, authorization)
    assert result.findings()
    escalation_notes = [n for n in result.notes if n.startswith("adaptive:")]
    assert escalation_notes
    assert any("depth" in note for note in escalation_notes)
    # Transform chains on findings must reflect what actually worked.
    for finding in result.findings():
        assert finding.transforms != ("identity",)


def test_adaptive_reports_the_extra_requests_it_spent(mock_config, authorization):
    """A plan that understated its own request count would defeat `redteam plan`."""
    config = mock_config(
        orchestrator="adaptive",
        probes=["direct.instruction_override"],
        targets=[{"id": "filtered", "plugin": "mock.llm", "options": {"profile": "balanced"}}],
    )
    result, _, _ = _run(config, authorization)
    assert any("beyond the planned baseline" in note for note in result.notes)


def test_adaptive_does_not_escalate_a_baseline_that_already_bypassed(
    mock_config, authorization
):
    config = mock_config(
        orchestrator="adaptive",
        probes=["direct.instruction_override"],
        targets=[{"id": "weak", "plugin": "mock.llm", "options": {"profile": "vulnerable"}}],
    )
    result, _, _ = _run(config, authorization)
    for finding in result.findings():
        assert finding.transforms == ("identity",)


def test_adaptive_gives_up_after_max_depth(mock_config, authorization):
    config = mock_config(
        orchestrator="adaptive",
        probes=["direct.instruction_override"],
        orchestrator_options={"max_depth": 1},
        targets=[{"id": "hard", "plugin": "mock.llm", "options": {"profile": "hardened"}}],
    )
    result, _, _ = _run(config, authorization)
    assert result.findings() == []


def test_adaptive_escalation_order_is_cheapest_first():
    """So the earliest success is also the most informative finding."""
    assert DEFAULT_ESCALATION[0] == "pad.noise"
    assert DEFAULT_ESCALATION.index("encoding.base64") > DEFAULT_ESCALATION.index(
        "unicode.zero_width"
    )


def test_adaptive_is_deterministic(mock_config, authorization):
    config = mock_config(
        orchestrator="adaptive",
        probes=["direct.instruction_override"],
        targets=[{"id": "filtered", "plugin": "mock.llm", "options": {"profile": "balanced"}}],
    )
    first, _, _ = _run(config, authorization)
    second, _, _ = _run(config, authorization)
    assert [a.transforms for a in first.attempts] == [a.transforms for a in second.attempts]


# --------------------------------------------------------------------------- #
# Registry hygiene
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("orchestrator_id", ORCHESTRATORS.names())
def test_every_orchestrator_describes_itself(orchestrator_id):
    orchestrator = ORCHESTRATORS.create(
        orchestrator_id, **_orchestrator_options(orchestrator_id)
    )
    assert orchestrator.description
    assert ORCHESTRATORS.entry(orchestrator_id).summary


@pytest.mark.parametrize("orchestrator_id", ORCHESTRATORS.names())
def test_every_orchestrator_completes_a_small_run(
    orchestrator_id, mock_config, authorization
):
    config = mock_config(
        orchestrator=orchestrator_id,
        orchestrator_options=_orchestrator_options(orchestrator_id),
        probes=["multiturn.crescendo" if orchestrator_id == "crescendo" else "direct.prefix_injection"],
    )
    result, _, _ = _run(config, authorization)
    assert result.attempts
    assert result.finished_at
