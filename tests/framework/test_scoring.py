"""Scoring.

Almost every test here is about the *denominator*. Attack success rate is the number
people read first and quote later, and the easiest way to make a target look secure
is to count attempts that never produced a verdict as passes. These tests fix the
arithmetic so that cannot happen by accident.
"""

from __future__ import annotations

from redteam.core.result import (
    AttemptResult,
    Outcome,
    Payload,
    Risk,
    RunResult,
    TargetResponse,
    Verdict,
)
from redteam.scoring.metrics import (
    RISK_WEIGHTS,
    compare,
    deduplicate_findings,
    resilience_score,
    summarize,
    summarize_attempts,
    top_findings,
)


def _attempt(
    outcome: Outcome,
    *,
    risk: Risk = Risk.HIGH,
    probe: str = "test.probe",
    payload_id: str = "p1",
    carrier: str = "prompt",
    target: str = "t1",
    transforms: tuple[str, ...] = ("identity",),
    technique: str = "technique",
    taxonomy: tuple[str, ...] = ("OWASP-LLM01",),
    score: float = 1.0,
    latency: float = 100.0,
    detector: str = "marker.echo",
) -> AttemptResult:
    payload = Payload(
        probe=probe,
        payload_id=payload_id,
        messages=(),
        objective="objective",
        risk=risk,
        carrier=carrier,
        technique=technique,
        taxonomy=taxonomy,
    )
    verdict = Verdict(detector=detector, outcome=outcome, score=score)
    return AttemptResult(
        attempt_id=f"{target}-{probe}-{payload_id}-{'+'.join(transforms)}",
        target=target,
        payload=payload,
        transforms=transforms,
        conversation=(),
        response=TargetResponse(text="x", latency_ms=latency),
        verdicts=(verdict,),
        outcome=outcome,
        score=score,
    )


# --------------------------------------------------------------------------- #
# The denominator
# --------------------------------------------------------------------------- #
def test_asr_counts_only_attempts_that_reached_a_verdict():
    metrics = summarize_attempts(
        [
            _attempt(Outcome.BYPASSED),
            _attempt(Outcome.BLOCKED, payload_id="p2"),
            _attempt(Outcome.SKIPPED, payload_id="p3"),
            _attempt(Outcome.ERROR, payload_id="p4"),
            _attempt(Outcome.INCONCLUSIVE, payload_id="p5"),
        ]
    )
    assert metrics.total == 5
    assert metrics.scored == 2  # bypassed + blocked only
    assert metrics.asr.bypassed == 1
    assert metrics.asr.percent == 50.0


def test_skips_are_not_folded_into_the_denominator():
    """Folding 40 skips in would manufacture a reassuring number out of missing
    coverage — the single most misleading thing this framework could report."""
    attempts = [_attempt(Outcome.BYPASSED)] + [
        _attempt(Outcome.SKIPPED, payload_id=f"s{i}") for i in range(40)
    ]
    metrics = summarize_attempts(attempts)
    assert metrics.asr.scored == 1
    assert metrics.asr.percent == 100.0  # 1 of 1 scored, not 1 of 41
    assert metrics.coverage_warning


def test_inconclusive_is_its_own_bucket():
    metrics = summarize_attempts(
        [_attempt(Outcome.INCONCLUSIVE), _attempt(Outcome.INCONCLUSIVE, payload_id="p2")]
    )
    assert metrics.inconclusive == 2
    assert metrics.scored == 0
    assert metrics.bypassed == 0


def test_rate_keeps_its_counts_alongside_the_percentage():
    """3/4 and 300/400 are the same percentage and very different evidence."""
    metrics = summarize_attempts(
        [_attempt(Outcome.BYPASSED), _attempt(Outcome.BLOCKED, payload_id="p2")]
    )
    assert str(metrics.asr) == "1/2 (50.0%)"


# --------------------------------------------------------------------------- #
# Coverage warnings
# --------------------------------------------------------------------------- #
def test_no_attempts_warns_that_nothing_was_established():
    assert "establishes nothing" in summarize_attempts([]).coverage_warning


def test_no_verdicts_warns_that_the_score_is_meaningless():
    metrics = summarize_attempts([_attempt(Outcome.ERROR), _attempt(Outcome.SKIPPED, payload_id="p2")])
    assert "meaningless" in metrics.coverage_warning


def test_partial_coverage_is_reported_with_a_proportion():
    attempts = [_attempt(Outcome.BLOCKED, payload_id=f"b{i}") for i in range(6)]
    attempts += [_attempt(Outcome.SKIPPED, payload_id=f"s{i}") for i in range(4)]
    metrics = summarize_attempts(attempts)
    assert "40%" in metrics.coverage_warning


def test_a_high_error_rate_is_flagged():
    attempts = [_attempt(Outcome.BLOCKED, payload_id=f"b{i}") for i in range(9)]
    attempts += [_attempt(Outcome.ERROR, payload_id="e1")]
    assert "target availability" in summarize_attempts(attempts).coverage_warning


def test_a_clean_full_run_has_no_warning():
    attempts = [_attempt(Outcome.BLOCKED, payload_id=f"b{i}") for i in range(10)]
    assert summarize_attempts(attempts).coverage_warning == ""


# --------------------------------------------------------------------------- #
# Resilience
# --------------------------------------------------------------------------- #
def test_resilience_is_1_when_nothing_got_through():
    assert resilience_score([_attempt(Outcome.BLOCKED)]) == 1.0


def test_resilience_is_0_when_everything_got_through():
    assert resilience_score([_attempt(Outcome.BYPASSED)]) == 0.0


def test_resilience_weights_by_risk():
    """A target must not look healthy by blocking a pile of cheap probes while a
    critical one gets through."""
    one_critical_through = resilience_score(
        [
            _attempt(Outcome.BYPASSED, risk=Risk.CRITICAL),
            *[_attempt(Outcome.BLOCKED, risk=Risk.LOW, payload_id=f"l{i}") for i in range(5)],
        ]
    )
    one_low_through = resilience_score(
        [
            _attempt(Outcome.BYPASSED, risk=Risk.LOW),
            *[_attempt(Outcome.BLOCKED, risk=Risk.LOW, payload_id=f"l{i}") for i in range(5)],
        ]
    )
    assert one_critical_through < one_low_through


def test_resilience_ignores_unscored_attempts():
    scored_only = resilience_score([_attempt(Outcome.BLOCKED)])
    with_noise = resilience_score(
        [
            _attempt(Outcome.BLOCKED),
            _attempt(Outcome.SKIPPED, payload_id="s"),
            _attempt(Outcome.ERROR, payload_id="e"),
        ]
    )
    assert scored_only == with_noise


def test_risk_weights_are_monotonic():
    weights = [RISK_WEIGHTS[r] for r in (Risk.CRITICAL, Risk.HIGH, Risk.MEDIUM, Risk.LOW, Risk.INFO)]
    assert weights == sorted(weights, reverse=True)


# --------------------------------------------------------------------------- #
# Breakdowns
# --------------------------------------------------------------------------- #
def test_carrier_breakdown_says_which_channel_got_through():
    metrics = summarize_attempts(
        [
            _attempt(Outcome.BYPASSED, carrier="tool_output"),
            _attempt(Outcome.BYPASSED, carrier="tool_output", payload_id="p2"),
            _attempt(Outcome.BLOCKED, carrier="prompt", payload_id="p3"),
        ]
    )
    assert metrics.by_carrier["tool_output"].percent == 100.0
    assert metrics.by_carrier["prompt"].percent == 0.0


def test_transform_breakdown_says_which_encoding_got_through():
    metrics = summarize_attempts(
        [
            _attempt(Outcome.BLOCKED, transforms=("identity",)),
            _attempt(Outcome.BYPASSED, transforms=("encoding.base64",), payload_id="p2"),
        ]
    )
    assert metrics.by_transform["identity"].percent == 0.0
    assert metrics.by_transform["encoding.base64"].percent == 100.0


def test_breakdowns_are_ordered_worst_first():
    metrics = summarize_attempts(
        [
            _attempt(Outcome.BLOCKED, target="safe"),
            _attempt(Outcome.BYPASSED, target="weak", payload_id="p2"),
        ]
    )
    assert list(metrics.by_target) == ["weak", "safe"]


def test_taxonomy_breakdown_expands_multiple_references():
    metrics = summarize_attempts(
        [_attempt(Outcome.BYPASSED, taxonomy=("OWASP-LLM01", "OWASP-LLM08"))]
    )
    assert set(metrics.by_taxonomy) == {"OWASP-LLM01", "OWASP-LLM08"}


def test_findings_by_risk_counts_only_findings():
    metrics = summarize_attempts(
        [
            _attempt(Outcome.BYPASSED, risk=Risk.CRITICAL),
            _attempt(Outcome.BLOCKED, risk=Risk.CRITICAL, payload_id="p2"),
        ]
    )
    assert metrics.by_risk == {"critical": 1}
    assert metrics.worst_risk == "critical"


def test_triggering_detectors_are_counted():
    metrics = summarize_attempts(
        [
            _attempt(Outcome.BYPASSED, detector="marker.echo"),
            _attempt(Outcome.BYPASSED, detector="marker.echo", payload_id="p2"),
            _attempt(Outcome.BYPASSED, detector="toolcall.forbidden", payload_id="p3"),
        ]
    )
    assert metrics.by_detector["marker.echo"] == 2
    assert metrics.by_detector["toolcall.forbidden"] == 1


def test_mean_latency_is_reported():
    metrics = summarize_attempts(
        [_attempt(Outcome.BLOCKED, latency=100.0), _attempt(Outcome.BLOCKED, payload_id="p2", latency=300.0)]
    )
    assert metrics.mean_latency_ms == 200.0


# --------------------------------------------------------------------------- #
# Triage
# --------------------------------------------------------------------------- #
def test_top_findings_are_ordered_by_risk_then_confidence():
    findings = top_findings(
        [
            _attempt(Outcome.BYPASSED, risk=Risk.LOW, payload_id="low"),
            _attempt(Outcome.BYPASSED, risk=Risk.CRITICAL, payload_id="crit", score=0.7),
            _attempt(Outcome.BYPASSED, risk=Risk.CRITICAL, payload_id="crit2", score=0.95),
            _attempt(Outcome.BLOCKED, risk=Risk.CRITICAL, payload_id="blocked"),
        ]
    )
    assert [f.payload.payload_id for f in findings] == ["crit2", "crit", "low"]


def test_top_findings_honours_the_limit():
    attempts = [_attempt(Outcome.BYPASSED, payload_id=f"p{i}") for i in range(10)]
    assert len(top_findings(attempts, limit=3)) == 3


def test_findings_group_by_probe_and_carrier():
    """Twelve payloads of one probe through one carrier is one defect with twelve
    pieces of evidence, not twelve defects."""
    attempts = [
        _attempt(Outcome.BYPASSED, probe="indirect.document", carrier="document", payload_id=f"f{i}")
        for i in range(12)
    ]
    attempts.append(
        _attempt(Outcome.BYPASSED, probe="indirect.webpage", carrier="webpage", payload_id="w")
    )
    grouped = deduplicate_findings(attempts)
    assert len(grouped) == 2
    assert len(grouped[("indirect.document", "document")]) == 12


def test_grouping_excludes_non_findings():
    assert deduplicate_findings([_attempt(Outcome.BLOCKED)]) == {}


def test_grouping_is_ordered_worst_first():
    attempts = [
        _attempt(Outcome.BYPASSED, probe="a.low", risk=Risk.LOW, carrier="prompt"),
        _attempt(Outcome.BYPASSED, probe="b.crit", risk=Risk.CRITICAL, carrier="document"),
    ]
    assert list(deduplicate_findings(attempts))[0][0] == "b.crit"


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #
def test_compare_identifies_fixes_and_regressions():
    baseline = [
        _attempt(Outcome.BYPASSED, payload_id="was_broken"),
        _attempt(Outcome.BLOCKED, payload_id="was_fine"),
        _attempt(Outcome.BYPASSED, payload_id="still_broken"),
    ]
    current = [
        _attempt(Outcome.BLOCKED, payload_id="was_broken"),
        _attempt(Outcome.BYPASSED, payload_id="was_fine"),
        _attempt(Outcome.BYPASSED, payload_id="still_broken"),
    ]
    diff = compare(baseline, current)
    assert len(diff["fixed"]) == 1 and "was_broken" in diff["fixed"][0]
    assert len(diff["regressed"]) == 1 and "was_fine" in diff["regressed"][0]
    assert len(diff["still_failing"]) == 1


def test_compare_flags_shrinking_coverage():
    """A run that dropped attempts is not a run that fixed them."""
    baseline = [_attempt(Outcome.BYPASSED, payload_id="a"), _attempt(Outcome.BYPASSED, payload_id="b")]
    current = [_attempt(Outcome.BYPASSED, payload_id="a")]
    diff = compare(baseline, current)
    assert len(diff["only_in_baseline"]) == 1
    assert diff["fixed"] == []  # 'b' vanished, it was not fixed


def test_compare_is_keyed_on_coordinates_not_order():
    baseline = [_attempt(Outcome.BYPASSED, payload_id="a"), _attempt(Outcome.BLOCKED, payload_id="b")]
    current = list(reversed([_attempt(Outcome.BYPASSED, payload_id="a"), _attempt(Outcome.BLOCKED, payload_id="b")]))
    diff = compare(baseline, current)
    assert diff["fixed"] == [] and diff["regressed"] == []


def test_compare_reports_both_success_rates():
    diff = compare([_attempt(Outcome.BYPASSED)], [_attempt(Outcome.BLOCKED)])
    assert diff["baseline_asr"]["percent"] == 100.0
    assert diff["current_asr"]["percent"] == 0.0


# --------------------------------------------------------------------------- #
# Integration with RunResult
# --------------------------------------------------------------------------- #
def test_summarize_reads_a_run_result():
    run = RunResult(run_id="r")
    run.add(_attempt(Outcome.BYPASSED))
    run.add(_attempt(Outcome.BLOCKED, payload_id="p2"))
    assert summarize(run).asr.percent == 50.0


def test_metrics_serialise_to_a_dict():
    payload = summarize_attempts([_attempt(Outcome.BYPASSED)]).to_dict()
    assert payload["attack_success_rate"]["percent"] == 100.0
    assert payload["resilience_score"] == 0.0
    assert "by_carrier" in payload
    assert "coverage_warning" in payload


def test_run_to_dict_embeds_metrics():
    run = RunResult(run_id="r")
    run.add(_attempt(Outcome.BYPASSED))
    assert run.to_dict()["metrics"]["counts"]["bypassed"] == 1
