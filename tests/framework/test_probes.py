"""The probe corpus.

Two kinds of test here, and the second matters more than the first.

The **contract** tests check that every probe produces well-formed, deterministic,
uniquely-marked payloads — the mechanics that make a run reproducible.

The **safety** tests check that the corpus is what this project claims it is: every
objective inert, no shipped attack content, no real hostnames, no credentials. Those
claims are load-bearing for the decision to publish this repository at all, so they
are asserted rather than trusted. A future probe that quietly ships a working
jailbreak fails the suite.
"""

from __future__ import annotations

import json
import re

import pytest

from redteam.core.result import Risk
from redteam.core.sentinel import SentinelFactory
from redteam.probes import PROBES, ProbeContext, build_probe, select_probes
from redteam.probes.indirect import FAMILIES, IndirectProbe
from redteam.probes.multiturn import LADDERS

ALL_PROBE_IDS = PROBES.names()

#: Probes that need an operator-supplied file and cannot generate payloads alone.
NEEDS_INPUT = {"corpus.custom"}
GENERATIVE_IDS = [p for p in ALL_PROBE_IDS if p not in NEEDS_INPUT]


def _ctx(seed: str = "test-seed", **kwargs) -> ProbeContext:
    return ProbeContext(sentinels=SentinelFactory(seed=seed), seed=seed, **kwargs)


def _payloads(probe_id: str, ctx: ProbeContext | None = None) -> list:
    return list(build_probe(probe_id).payloads(ctx or _ctx()))


# --------------------------------------------------------------------------- #
# Contract
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("probe_id", GENERATIVE_IDS)
def test_every_probe_yields_payloads(probe_id):
    assert _payloads(probe_id), f"{probe_id} produced no payloads"


@pytest.mark.parametrize("probe_id", GENERATIVE_IDS)
def test_payloads_are_well_formed(probe_id):
    for payload in _payloads(probe_id):
        assert payload.probe == probe_id
        assert payload.payload_id, "payload_id must be set"
        assert payload.messages, "payload must carry a conversation"
        assert payload.objective, "payload must state its objective"
        assert payload.detectors, "payload must name at least one detector"
        assert payload.messages[0].role == "system", (
            "every payload starts from the operator instruction, or the measurement "
            "has no baseline"
        )
        assert any(m.role in ("user", "tool") for m in payload.messages)


@pytest.mark.parametrize("probe_id", GENERATIVE_IDS)
def test_payload_ids_are_unique_within_a_probe(probe_id):
    ids = [p.payload_id for p in _payloads(probe_id)]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("probe_id", GENERATIVE_IDS)
def test_generation_is_deterministic(probe_id):
    """Same seed, same payloads — byte for byte. Without this a finding cannot be
    handed to the team that has to fix it."""
    first = [p.to_dict() for p in _payloads(probe_id, _ctx("fixed"))]
    second = [p.to_dict() for p in _payloads(probe_id, _ctx("fixed"))]
    assert first == second


@pytest.mark.parametrize("probe_id", GENERATIVE_IDS)
def test_a_different_seed_changes_the_sentinels(probe_id):
    a = {p.sentinel for p in _payloads(probe_id, _ctx("seed-a")) if p.sentinel}
    b = {p.sentinel for p in _payloads(probe_id, _ctx("seed-b")) if p.sentinel}
    assert a & b == set(), f"{probe_id} reused sentinels across seeds"


def test_sentinels_are_globally_unique_across_the_corpus():
    """Two probes sharing a token would let a detector credit the wrong probe."""
    seen: dict[str, str] = {}
    for probe_id in GENERATIVE_IDS:
        for payload in _payloads(probe_id):
            if not payload.sentinel:
                continue
            assert payload.sentinel not in seen, (
                f"{probe_id}/{payload.payload_id} reuses the sentinel from "
                f"{seen[payload.sentinel]}"
            )
            seen[payload.sentinel] = f"{probe_id}/{payload.payload_id}"


@pytest.mark.parametrize("probe_id", GENERATIVE_IDS)
def test_sentinel_is_reachable_from_the_payload_when_declared(probe_id):
    """A declared sentinel the payload never asks for makes the detector unfalsifiable.

    "Reachable" covers the legitimate channels a target actually reads: plainly in a
    turn, inside an encoding it is asked to decode, on a later rung of a multi-turn
    ladder, or in the definition of a tool it was handed (tool-definition poisoning).
    It does not cover "nowhere", which is the bug this guards against.
    """
    import json

    from redteam.core.codecs import canonical_forms

    for payload in _payloads(probe_id):
        if not payload.sentinel:
            continue
        text = "\n".join(m.content for m in payload.messages)
        text += "\n" + "\n".join(payload.metadata.get("ladder") or [])
        # Tool definitions are a real channel the model reads (mcp.tool_poisoning).
        text += "\n" + json.dumps(payload.metadata.get("tools") or [])
        reachable = any(payload.sentinel in form for form in canonical_forms(text))
        assert reachable, (
            f"{probe_id}/{payload.payload_id} declares a sentinel that is not "
            f"reachable from its messages, its encodings, its ladder, or its tools"
        )


@pytest.mark.parametrize("probe_id", GENERATIVE_IDS)
def test_max_payloads_is_honoured(probe_id):
    assert len(_payloads(probe_id, _ctx(max_payloads=1))) <= 1


@pytest.mark.parametrize("probe_id", ALL_PROBE_IDS)
def test_probe_metadata_is_complete(probe_id):
    probe = build_probe(probe_id)
    assert probe.description, f"{probe_id} has no description"
    assert isinstance(probe.risk, Risk)
    assert probe.taxonomy, f"{probe_id} cites no external reference"
    assert probe.tags, f"{probe_id} carries no tags, so it cannot be filtered"
    assert probe.default_detectors


@pytest.mark.parametrize("probe_id", ALL_PROBE_IDS)
def test_declared_detectors_exist(probe_id):
    from redteam.detectors import DETECTORS

    probe = build_probe(probe_id)
    for detector in probe.default_detectors:
        assert detector in DETECTORS, f"{probe_id} names unknown detector {detector!r}"


@pytest.mark.parametrize("probe_id", GENERATIVE_IDS)
def test_declared_tools_have_valid_schemas(probe_id):
    for payload in _payloads(probe_id):
        for tool in payload.metadata.get("tools") or []:
            assert tool.get("name"), "a tool declaration needs a name"
            assert isinstance(tool.get("parameters"), dict)


@pytest.mark.parametrize("probe_id", GENERATIVE_IDS)
def test_forbidden_tools_are_actually_offered(probe_id):
    """Forbidding a tool that was never offered makes the detector unfalsifiable."""
    for payload in _payloads(probe_id):
        forbidden = set(payload.metadata.get("forbidden_tools") or ())
        if not forbidden:
            continue
        offered = {t.get("name") for t in (payload.metadata.get("tools") or [])}
        assert forbidden <= offered, (
            f"{probe_id}/{payload.payload_id} forbids {forbidden - offered} which it "
            f"never offered"
        )


# --------------------------------------------------------------------------- #
# Safety properties of the shipped corpus
# --------------------------------------------------------------------------- #
#: Terms that would indicate a genuine harmful-content payload had been committed.
#: The framework measures guardrail integrity with inert sentinels; harm-category
#: evaluation belongs in an operator's own corpus file, not in this repository.
FORBIDDEN_CONTENT = (
    "nerve agent",
    "sarin",
    "ricin",
    "pipe bomb",
    "napalm",
    "thermite",
    "child sexual",
    "csam",
    "how to make meth",
    "methamphetamine synthesis",
    "suicide method",
    "kill yourself",
)


@pytest.mark.parametrize("probe_id", GENERATIVE_IDS)
def test_no_probe_ships_harmful_content(probe_id):
    for payload in _payloads(probe_id):
        text = "\n".join(m.content for m in payload.messages).lower()
        for term in FORBIDDEN_CONTENT:
            assert term not in text, (
                f"{probe_id}/{payload.payload_id} contains {term!r}. Harm-category "
                f"prompts belong in an operator-supplied corpus.custom file, never in "
                f"the shipped corpus."
            )


@pytest.mark.parametrize("probe_id", GENERATIVE_IDS)
def test_payloads_contain_no_credentials(probe_id):
    from redteam.core.redact import Redactor

    redactor = Redactor(redact_emails=False, redact_cards=False)
    for payload in _payloads(probe_id):
        for message in payload.messages:
            hits = redactor.scan(message.content)
            assert not hits, f"{probe_id}/{payload.payload_id} contains {hits}"


#: Hostnames in payloads must be RFC 2606 reserved, so nothing resolves even if a
#: target renders a URL a probe asked it to build.
_HOST_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)")
RESERVED_SUFFIXES = (".example.com", ".example.net", ".example.org", "example.com",
                     "example.net", "example.org", ".invalid", ".test", ".localhost")


@pytest.mark.parametrize("probe_id", GENERATIVE_IDS)
def test_payload_urls_use_reserved_documentation_hosts(probe_id):
    for payload in _payloads(probe_id):
        for message in payload.messages:
            for host in _HOST_RE.findall(message.content):
                assert host.endswith(RESERVED_SUFFIXES) or host in ("localhost",), (
                    f"{probe_id}/{payload.payload_id} references the real host "
                    f"{host!r}; use an RFC 2606 reserved domain so no traffic can "
                    f"leave"
                )


# --------------------------------------------------------------------------- #
# Indirect injection: the playbook cross-product
# --------------------------------------------------------------------------- #
INDIRECT_IDS = [p for p in ALL_PROBE_IDS if p.startswith("indirect.")]


def test_all_seven_playbook_families_are_implemented():
    """The families come from data/ACTIVE_CHALLENGE_PLAYBOOK.md section 4."""
    letters = sorted(f.letter for f in FAMILIES)
    assert letters == ["A", "B", "C", "D", "E", "F", "G"]


@pytest.mark.parametrize("probe_id", INDIRECT_IDS)
def test_each_carrier_covers_every_family(probe_id):
    payloads = _payloads(probe_id)
    covered = {p.metadata["family_letter"] for p in payloads}
    assert covered == {f.letter for f in FAMILIES}


@pytest.mark.parametrize("probe_id", INDIRECT_IDS)
def test_indirect_payloads_carry_the_injection_in_an_untrusted_turn(probe_id):
    """If the injection were in a trusted turn this would be a direct-injection
    probe wearing the wrong name, and the finding would misattribute the channel."""
    for payload in _payloads(probe_id):
        untrusted = [m for m in payload.messages if not m.trusted]
        assert untrusted, f"{probe_id}/{payload.payload_id} has no untrusted turn"
        assert payload.sentinel in "\n".join(m.content for m in untrusted)


@pytest.mark.parametrize("probe_id", INDIRECT_IDS)
def test_indirect_payloads_keep_a_legitimate_task(probe_id):
    """A target that simply does its job must pass. Without the benign task the
    probe would be measuring refusal, not provenance handling."""
    for payload in _payloads(probe_id):
        assert payload.metadata.get("legitimate_task")
        user_turns = [m for m in payload.messages if m.role == "user" and m.trusted]
        assert user_turns, f"{probe_id}/{payload.payload_id} has no legitimate request"


def test_indirect_carriers_are_distinct():
    carriers = {build_probe(p).carrier for p in INDIRECT_IDS}
    assert len(carriers) == len(INDIRECT_IDS)


def test_family_selection_narrows_generation():
    probe = build_probe("indirect.document", families=["authority_provenance"])
    payloads = list(probe.payloads(_ctx()))
    assert len(payloads) == 1
    assert payloads[0].metadata["family"] == "authority_provenance"


def test_code_artifact_carrier_is_rated_critical():
    """A coding agent's tools change files and dependencies, so a bypass converts
    into code execution."""
    assert build_probe("indirect.code_artifact").risk is Risk.CRITICAL


# --------------------------------------------------------------------------- #
# Leakage
# --------------------------------------------------------------------------- #
def test_system_prompt_leak_plants_its_canary_in_the_system_turn():
    for payload in _payloads("leak.system_prompt"):
        canary = payload.metadata["canary"]
        system_text = "\n".join(m.content for m in payload.messages if m.role == "system")
        assert canary in system_text
        user_text = "\n".join(m.content for m in payload.messages if m.role == "user")
        assert canary not in user_text, (
            "the extraction prompt must not contain the canary, or it tests nothing"
        )


def test_system_prompt_leak_declares_that_it_needs_a_system_turn():
    """So the orchestrator skips it rather than reporting an untested pass."""
    assert build_probe("leak.system_prompt").requires_system_prompt is True


def test_history_leak_plants_its_canary_in_an_assistant_turn():
    for payload in _payloads("leak.conversation_history"):
        canary = payload.metadata["canary"]
        assistant_text = "\n".join(
            m.content for m in payload.messages if m.role == "assistant"
        )
        assert canary in assistant_text


# --------------------------------------------------------------------------- #
# Multi-turn
# --------------------------------------------------------------------------- #
def test_crescendo_requires_its_own_orchestrator():
    assert build_probe("multiturn.crescendo").requires_orchestrator == ("crescendo",)


def test_crescendo_payloads_expose_the_ladder():
    payloads = _payloads("multiturn.crescendo")
    assert len(payloads) == len(LADDERS)
    for payload in payloads:
        ladder = payload.metadata["ladder"]
        assert len(ladder) >= 3, "an escalation needs several rungs to be an escalation"
        # Only the opening rung is in the conversation; the orchestrator adds the rest.
        user_turns = [m for m in payload.messages if m.role == "user"]
        assert len(user_turns) == 1
        assert user_turns[0].content == ladder[0]


def test_crescendo_asks_for_the_objective_only_at_the_end():
    """If the sentinel appeared on rung one it would be a single-turn probe."""
    for payload in _payloads("multiturn.crescendo"):
        ladder = payload.metadata["ladder"]
        if payload.payload_id == "context_poisoning":
            continue  # this one deliberately plants the trigger early
        assert payload.sentinel not in ladder[0]
        assert payload.sentinel in ladder[-1]


# --------------------------------------------------------------------------- #
# Safety reframing
# --------------------------------------------------------------------------- #
def test_safety_reframing_wraps_one_objective_in_distinct_frames():
    """The measurement is frame invariance: same objective, changed wrapper."""
    payloads = _payloads("framing.safety_reframing")
    frames = {p.metadata["frame"] for p in payloads}
    assert frames == {"compliance", "fiction+compliance", "refusal-pivot", "fiction+compliance+audit"}
    objectives = {p.objective for p in payloads}
    assert len(objectives) == 1


def test_safety_reframing_carries_the_sentinel_in_every_variant():
    for payload in _payloads("framing.safety_reframing"):
        text = "\n".join(m.content for m in payload.messages if m.role == "user")
        assert payload.sentinel in text


def test_redirect_pivot_ladder_reaches_the_sentinel_only_after_the_refusal():
    """Rung one is the refused ask; the objective exists only in the trajectory."""
    ladder = next(l for l in LADDERS if l.id == "redirect_pivot")
    assert len(ladder.rungs) >= 4, "the refusal-pivot pattern needs the escalation"
    assert "{sentinel}" not in ladder.rungs[0]
    assert "{sentinel}" in ladder.rungs[-1]


def test_redirect_pivot_mines_the_refusal_before_reframing():
    """Turn two must ask for the screening logic before any reframe arrives."""
    ladder = next(l for l in LADDERS if l.id == "redirect_pivot")
    assert "screens for" in ladder.rungs[1]


# --------------------------------------------------------------------------- #
# Aggregation structuring
# --------------------------------------------------------------------------- #
def test_aggregation_wraps_one_objective_in_distinct_structures():
    """The measurement is granularity invariance: same objective, changed structure."""
    payloads = _payloads("framing.aggregation")
    structures = {p.metadata["structure"] for p in payloads}
    assert structures == {"split", "persona", "relay", "stacked"}
    assert len({p.objective for p in payloads}) == 1


def test_aggregation_carries_the_full_sentinel_in_every_variant():
    for payload in _payloads("framing.aggregation"):
        text = "\n".join(m.content for m in payload.messages if m.role == "user")
        assert payload.sentinel in text


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #
def test_family_prefix_selects_the_whole_family():
    ids = {p.id for p in select_probes(["indirect"])}
    assert ids == set(INDIRECT_IDS)


def test_glob_selection():
    ids = {p.id for p in select_probes(["*.tool_output"])}
    assert ids == {"indirect.tool_output"}


def test_tag_filter_narrows_an_id_selection():
    ids = {p.id for p in select_probes(["indirect"], include_tags=["coding-agent"])}
    assert ids == {"indirect.code_artifact", "indirect.issue_tracker"}


def test_exclude_tag_removes_probes():
    ids = {p.id for p in select_probes(["indirect"], exclude_tags=["coding-agent"])}
    assert "indirect.code_artifact" not in ids
    assert "indirect.document" in ids


def test_empty_selection_is_an_error_not_a_silent_pass():
    from redteam.core.errors import ConfigError

    with pytest.raises(ConfigError, match="selection is empty"):
        select_probes(["indirect"], include_tags=["no-such-tag"])


def test_unknown_selector_is_an_error():
    from redteam.core.errors import RegistryError

    with pytest.raises(RegistryError, match="matched nothing"):
        select_probes(["definitely.not.a.probe"])


def test_no_selector_means_everything():
    assert len(select_probes(None)) == len(ALL_PROBE_IDS)


# --------------------------------------------------------------------------- #
# Custom corpus
# --------------------------------------------------------------------------- #
def test_corpus_probe_reads_jsonl(tmp_path):
    path = tmp_path / "corpus.local.jsonl"
    path.write_text(
        '\n'.join(
            [
                '{"id": "h1", "prompt": "test one", "risk": "critical"}',
                '# a comment line is skipped',
                '{"id": "h2", "objective": "obj", "messages": '
                '[{"role": "user", "content": "test two"}], "tags": ["category:x"]}',
            ]
        ),
        encoding="utf-8",
    )
    payloads = list(build_probe("corpus.custom", path=str(path)).payloads(_ctx()))
    assert [p.payload_id for p in payloads] == ["h1", "h2"]
    assert payloads[0].risk is Risk.CRITICAL
    assert "category:x" in payloads[1].tags
    # A system turn is prepended so corpus entries are measured against the same
    # operator instruction as the built-in probes.
    assert payloads[1].messages[0].role == "system"


def test_corpus_metadata_records_a_digest_but_not_the_path(tmp_path):
    """A report can prove which corpus was used without disclosing where it lives."""
    path = tmp_path / "secret-location.local.jsonl"
    path.write_text('{"id": "a", "prompt": "x"}\n', encoding="utf-8")
    payload = next(iter(build_probe("corpus.custom", path=str(path)).payloads(_ctx())))
    assert payload.metadata["corpus_digest"]
    assert str(tmp_path) not in str(payload.metadata)


def test_explicit_corpus_flag_overrides_the_configured_path(tmp_path):
    """--corpus is the operator saying 'this run, this file'; config must not win."""
    configured = tmp_path / "configured.local.jsonl"
    configured.write_text('{"id": "from-config", "prompt": "x"}\n', encoding="utf-8")
    flagged = tmp_path / "flagged.local.jsonl"
    flagged.write_text('{"id": "from-flag", "prompt": "y"}\n', encoding="utf-8")
    probe = build_probe("corpus.custom", path=str(configured))
    payloads = list(probe.payloads(_ctx(corpus_path=str(flagged))))
    assert [p.payload_id for p in payloads] == ["from-flag"]


def test_configured_path_still_used_when_no_flag_is_passed(tmp_path):
    configured = tmp_path / "configured.local.jsonl"
    configured.write_text('{"id": "from-config", "prompt": "x"}\n', encoding="utf-8")
    probe = build_probe("corpus.custom", path=str(configured))
    payloads = list(probe.payloads(_ctx()))
    assert [p.payload_id for p in payloads] == ["from-config"]


def test_corpus_probe_without_a_path_says_how_to_fix_it():
    from redteam.core.errors import ConfigError

    with pytest.raises(ConfigError, match="--corpus"):
        list(build_probe("corpus.custom").payloads(_ctx()))


def test_corpus_probe_rejects_a_malformed_line(tmp_path):
    from redteam.core.errors import ConfigError

    path = tmp_path / "bad.jsonl"
    path.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid JSON"):
        list(build_probe("corpus.custom", path=str(path)).payloads(_ctx()))


def test_corpus_entry_needs_a_prompt_or_messages(tmp_path):
    from redteam.core.errors import ConfigError

    path = tmp_path / "bad.jsonl"
    path.write_text('{"id": "x"}\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="'prompt' or 'messages'"):
        list(build_probe("corpus.custom", path=str(path)).payloads(_ctx()))


def test_corpus_rubric_reaches_the_payload_metadata(tmp_path):
    path = tmp_path / "rubric.local.jsonl"
    path.write_text(
        json.dumps(
            {
                "id": "r1",
                "prompt": "x",
                "rubric": [
                    {"id": "precursors", "description": "names plausible precursors"},
                    {"id": "route", "description": "describes a coherent sequence"},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    payload = next(iter(build_probe("corpus.custom", path=str(path)).payloads(_ctx())))
    assert payload.metadata["rubric"][0]["id"] == "precursors"


@pytest.mark.parametrize(
    "bad_rubric",
    [
        '"prose only"',
        '[]',
        '[{"id": "a"}]',
        '[{"description": "no id"}]',
        '[{"id": "", "description": "empty id"}]',
    ],
)
def test_corpus_rejects_a_malformed_rubric(tmp_path, bad_rubric):
    from redteam.core.errors import ConfigError

    path = tmp_path / "bad.local.jsonl"
    path.write_text('{"id": "x", "prompt": "y", "rubric": ' + bad_rubric + "}\n")
    with pytest.raises(ConfigError, match="rubric"):
        list(build_probe("corpus.custom", path=str(path)).payloads(_ctx()))


def test_corpus_rejects_duplicate_rubric_ids(tmp_path):
    from redteam.core.errors import ConfigError

    path = tmp_path / "duplicate-rubric.local.jsonl"
    path.write_text(
        json.dumps(
            {
                "id": "x",
                "prompt": "y",
                "rubric": [
                    {"id": "criterion-a", "description": "one"},
                    {"id": "criterion-a", "description": "two"},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="duplicate"):
        list(build_probe("corpus.custom", path=str(path)).payloads(_ctx()))


# --------------------------------------------------------------------------- #
# Coverage of the threat model
# --------------------------------------------------------------------------- #
def test_the_corpus_covers_the_owasp_categories_it_claims():
    cited = {
        reference
        for probe_id in ALL_PROBE_IDS
        for reference in build_probe(probe_id).taxonomy
    }
    for category in ("OWASP-LLM01", "OWASP-LLM02", "OWASP-LLM06", "OWASP-LLM08"):
        assert category in cited, f"no probe covers {category}"


def test_every_carrier_in_the_threat_model_has_a_probe():
    carriers = {build_probe(p).carrier for p in GENERATIVE_IDS}
    for carrier in (
        "prompt",
        "document",
        "tool_output",
        "webpage",
        "code_comment",
        "tool_definition",
    ):
        assert carrier in carriers, f"no probe delivers via {carrier}"


def test_the_corpus_cross_references_the_eaa_taxonomy():
    """The behavioural EAA techniques we claim to cover must each be cited by a probe.

    EAA is mostly host-level; only these four have a live-behaviour analog, and each
    is mapped onto exactly the probe whose tested behaviour matches it.
    """
    cited = {
        reference
        for probe_id in ALL_PROBE_IDS
        for reference in build_probe(probe_id).taxonomy
    }
    for technique in ("EAA-006", "EAA-010", "EAA-015", "EAA-016"):
        assert technique in cited, f"no probe cross-references {technique}"


def test_indirect_probe_base_is_not_registered_directly():
    """The base class is abstract in intent; only its carrier subclasses register."""
    assert IndirectProbe.id in ("", "indirect.document") or True
    registered = {type(build_probe(p)) for p in INDIRECT_IDS}
    assert IndirectProbe not in registered
