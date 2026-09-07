"""CLI behaviour and exit codes.

The exit-code contract is what a pipeline actually consumes, so it is pinned here
rather than left to inspection:

``0``
    Success — for ``run``, no finding at or above the threshold.
``1``
    Findings, or a validation failure. The target has a problem.
``2``
    The operator asked for something invalid or unauthorized. Nothing was sent.

Keeping 1 and 2 distinct is the point: "the target has a vulnerability" and "your
authorization expired" must not look the same to CI.
"""

from __future__ import annotations

import json

import pytest

from redteam.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main


@pytest.fixture
def offline_config(tmp_path):
    """A config whose targets are all offline, so no authorization file is needed."""

    def build(**overrides):
        data = {
            "seed": "cli-test",
            "orchestrator": "sweep",
            "targets": [
                {"id": "rag", "plugin": "mock.llm", "options": {"profile": "balanced"}}
            ],
            "probes": ["direct.prefix_injection"],
            "transforms": ["identity"],
            "requests_per_minute": 0,
            "output_dir": str(tmp_path / "runs"),
            "formats": ["json"],
        }
        data.update(overrides)
        path = tmp_path / "config.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return str(path)

    return build


@pytest.fixture
def auth_file(tmp_path, authorization_record):
    path = tmp_path / "authorization.json"
    path.write_text(json.dumps(authorization_record), encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------- #
# Top level
# --------------------------------------------------------------------------- #
def test_no_command_prints_help_and_returns_usage(capsys):
    assert main([]) == EXIT_USAGE
    assert "redteam" in capsys.readouterr().out


def test_version(capsys):
    assert main(["--version"]) == EXIT_OK
    assert "redteam" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# list
# --------------------------------------------------------------------------- #
def test_list_shows_every_registry(capsys):
    assert main(["list"]) == EXIT_OK
    out = capsys.readouterr().out
    for kind in ("probes", "targets", "detectors", "transforms", "orchestrators", "reporters"):
        assert kind in out


def test_list_one_registry_as_json(capsys):
    assert main(["list", "probes", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert "probes" in payload
    assert any(entry["id"] == "indirect.document" for entry in payload["probes"])
    assert all(entry["summary"] for entry in payload["probes"])


def test_list_verbose_shows_tags(capsys):
    assert main(["list", "probes", "--verbose"]) == EXIT_OK
    assert "tags:" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# plan
# --------------------------------------------------------------------------- #
def test_plan_reports_counts_without_sending(offline_config, capsys):
    assert main(["plan", "--config", offline_config()]) == EXIT_OK
    out = capsys.readouterr().out
    assert "attempts" in out
    assert "request(s)" in out
    assert "attempts by probe" in out


def test_plan_as_json(offline_config, capsys):
    assert main(["plan", "--config", offline_config(), "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["sendable"] > 0
    assert payload["orchestrator"] == "sweep"


def test_plan_can_show_payloads(offline_config, capsys):
    assert main(["plan", "--config", offline_config(), "--show-payloads"]) == EXIT_OK
    assert "payloads:" in capsys.readouterr().out


def test_plan_lists_skips_with_reasons(offline_config, capsys):
    config = offline_config(probes=["multiturn.crescendo"])
    assert main(["plan", "--config", config]) == EXIT_OK
    out = capsys.readouterr().out
    assert "skipped" in out
    assert "not passes" in out


def test_plan_refuses_a_live_target_without_authorization(tmp_path, capsys):
    path = tmp_path / "live.json"
    path.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "id": "prod",
                        "plugin": "http.openai_compat",
                        "options": {"url": "https://api.example.com/v1/chat", "model": "m"},
                    }
                ],
                "probes": ["direct.prefix_injection"],
            }
        ),
        encoding="utf-8",
    )
    assert main(["plan", "--config", str(path)]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "NOT AUTHORIZED" in err
    assert "redteam init" in err


def test_plan_refuses_a_denylisted_target(tmp_path, authorization_record, capsys):
    authorization_record["scope"]["targets"].append("https://blocked.example.com/*")
    authorization_record["scope"]["deny"] = ["blocked.example.com"]
    auth_path = tmp_path / "authorization.json"
    auth_path.write_text(json.dumps(authorization_record), encoding="utf-8")
    path = tmp_path / "blocked.json"
    path.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "id": "blocked",
                        "plugin": "http.openai_compat",
                        "options": {
                            "url": "https://blocked.example.com/api",
                            "model": "m",
                        },
                    }
                ],
                "probes": ["direct.prefix_injection"],
            }
        ),
        encoding="utf-8",
    )
    assert main(["plan", "--config", str(path), "--auth", str(auth_path)]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "REFUSED" in err
    assert "not configurable" in err


# --------------------------------------------------------------------------- #
# run
# --------------------------------------------------------------------------- #
def test_run_against_a_hardened_target_exits_zero(offline_config, capsys):
    config = offline_config(
        targets=[{"id": "hard", "plugin": "mock.llm", "options": {"profile": "hardened"}}],
        probes=["indirect.document"],
    )
    assert main(["run", "--config", config, "--quiet"]) == EXIT_OK


def test_run_with_findings_exits_one(offline_config):
    config = offline_config(probes=["indirect.document"])
    assert main(["run", "--config", config, "--quiet"]) == EXIT_FINDINGS


def test_fail_on_threshold_is_respected(offline_config):
    """A medium finding must not fail a run gated on critical."""
    config = offline_config(
        probes=["direct.prefix_injection"],
        targets=[{"id": "weak", "plugin": "mock.llm", "options": {"profile": "vulnerable"}}],
    )
    assert main(["run", "--config", config, "--quiet", "--fail-on", "critical"]) == EXIT_OK
    assert main(["run", "--config", config, "--quiet", "--fail-on", "low"]) == EXIT_FINDINGS


def test_run_writes_the_requested_artifacts(offline_config, tmp_path):
    config = offline_config()
    assert main(
        [
            "run",
            "--config",
            config,
            "--quiet",
            "--out",
            str(tmp_path / "artifacts"),
            "--format",
            "json",
            "--format",
            "markdown",
        ]
    ) in (EXIT_OK, EXIT_FINDINGS)
    written = list((tmp_path / "artifacts").iterdir())
    assert {p.suffix for p in written} == {".json", ".md"}


def test_run_prints_a_console_report_unless_quiet(offline_config, capsys):
    main(["run", "--config", offline_config()])
    out = capsys.readouterr().out
    assert "SUMMARY" in out
    assert "attack success rate" in out


def test_dry_run_is_an_alias_for_plan(offline_config, capsys):
    assert main(["run", "--config", offline_config(), "--dry-run"]) == EXIT_OK
    assert "attempts" in capsys.readouterr().out


def test_cli_overrides_the_config(offline_config, capsys):
    config = offline_config(probes=["direct.prefix_injection"])
    assert main(["plan", "--config", config, "--probe", "indirect.webpage", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["probes"] == ["indirect.webpage"]


def test_target_filter_restricts_the_run(offline_config, capsys):
    config = offline_config(
        targets=[
            {"id": "a", "plugin": "mock.llm", "options": {"profile": "balanced"}},
            {"id": "b", "plugin": "mock.llm", "options": {"profile": "hardened"}},
        ]
    )
    assert main(["plan", "--config", config, "--target", "b", "--json"]) == EXIT_OK
    assert list(json.loads(capsys.readouterr().out)["targets"]) == ["b"]


def test_unknown_target_filter_lists_the_available_ones(offline_config, capsys):
    assert main(["plan", "--config", offline_config(), "--target", "nope"]) == EXIT_USAGE
    assert "which the config does not define" in capsys.readouterr().err


def test_max_payloads_per_probe_samples(offline_config, capsys):
    config = offline_config(probes=["indirect"])
    assert main(["plan", "--config", config, "--max-payloads-per-probe", "1", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["counts"]["sendable"] == len(payload["probes"])


def test_tag_filter_narrows_the_probe_set(offline_config, capsys):
    config = offline_config(probes=["indirect"])
    assert main(["plan", "--config", config, "--tag", "coding-agent", "--json"]) == EXIT_OK
    assert set(json.loads(capsys.readouterr().out)["probes"]) == {
        "indirect.code_artifact",
        "indirect.issue_tracker",
    }


def test_missing_config_is_a_usage_error(capsys):
    assert main(["plan", "--config", "/nonexistent/config.json"]) == EXIT_USAGE
    assert "config error" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
def test_report_rerenders_a_saved_run(offline_config, tmp_path, capsys):
    out_dir = tmp_path / "artifacts"
    main(["run", "--config", offline_config(), "--quiet", "--out", str(out_dir)])
    artifact = next(out_dir.glob("*.json"))
    capsys.readouterr()

    assert main(["report", str(artifact), "--format", "markdown"]) == EXIT_OK
    assert "## Summary" in capsys.readouterr().out


def test_report_can_write_to_a_file(offline_config, tmp_path, capsys):
    out_dir = tmp_path / "artifacts"
    main(["run", "--config", offline_config(), "--quiet", "--out", str(out_dir)])
    artifact = next(out_dir.glob("*.json"))
    destination = tmp_path / "report.html"

    assert main(["report", str(artifact), "--format", "html", "--out", str(destination)]) == EXIT_OK
    assert destination.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")


def test_report_on_a_missing_file_is_a_usage_error(capsys):
    assert main(["report", "/nonexistent/run.json"]) == EXIT_USAGE
    assert "not found" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# compare
# --------------------------------------------------------------------------- #
def test_compare_identical_runs_exits_zero(offline_config, tmp_path, capsys):
    out_dir = tmp_path / "artifacts"
    main(["run", "--config", offline_config(), "--quiet", "--out", str(out_dir)])
    artifact = next(out_dir.glob("*.json"))
    capsys.readouterr()

    assert main(["compare", str(artifact), str(artifact)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "regressed      : 0" in out


def test_compare_detects_a_regression_and_exits_one(offline_config, tmp_path, capsys):
    """The CI regression gate."""
    hardened = offline_config(
        targets=[{"id": "rag", "plugin": "mock.llm", "options": {"profile": "hardened"}}],
        probes=["indirect.document"],
    )
    main(["run", "--config", hardened, "--quiet", "--out", str(tmp_path / "before")])
    weak = offline_config(
        targets=[{"id": "rag", "plugin": "mock.llm", "options": {"profile": "balanced"}}],
        probes=["indirect.document"],
    )
    main(["run", "--config", weak, "--quiet", "--out", str(tmp_path / "after")])
    capsys.readouterr()

    baseline = next((tmp_path / "before").glob("*.json"))
    current = next((tmp_path / "after").glob("*.json"))
    assert main(["compare", str(baseline), str(current)]) == EXIT_FINDINGS
    assert "regressed" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def test_scan_finds_credentials_and_exits_one(tmp_path, capsys):
    target = tmp_path / "notes.txt"
    target.write_text("token AKIAABCDEFGHIJKLMNOP\n", encoding="utf-8")
    assert main(["scan", str(target)]) == EXIT_FINDINGS
    assert "aws_access_key" in capsys.readouterr().out


def test_scan_never_prints_the_secret_value(tmp_path, capsys):
    target = tmp_path / "notes.txt"
    target.write_text("token AKIAABCDEFGHIJKLMNOP\n", encoding="utf-8")
    main(["scan", str(target)])
    assert "AKIAABCDEFGHIJKLMNOP" not in capsys.readouterr().out


def test_scan_of_a_clean_file_exits_zero(tmp_path, capsys):
    target = tmp_path / "notes.txt"
    target.write_text("nothing sensitive here\n", encoding="utf-8")
    assert main(["scan", str(target)]) == EXIT_OK
    assert "no credentials or PII" in capsys.readouterr().out


def test_scan_walks_a_directory(tmp_path, capsys):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.txt").write_text("AKIAABCDEFGHIJKLMNOP", encoding="utf-8")
    assert main(["scan", str(tmp_path)]) == EXIT_FINDINGS


def test_scan_fix_writes_redacted_copies(tmp_path, capsys):
    target = tmp_path / "notes.txt"
    target.write_text("token AKIAABCDEFGHIJKLMNOP\n", encoding="utf-8")
    fixed = tmp_path / "clean"
    main(["scan", str(target), "--fix", str(fixed)])
    output = (fixed / "notes.txt").read_text(encoding="utf-8")
    assert "AKIAABCDEFGHIJKLMNOP" not in output
    assert "[REDACTED:aws_access_key]" in output


def test_scan_of_a_missing_path_is_a_usage_error(capsys):
    assert main(["scan", "/nonexistent/path"]) == EXIT_USAGE


# --------------------------------------------------------------------------- #
# authz
# --------------------------------------------------------------------------- #
def test_authz_summarises_the_record(auth_file, capsys):
    assert main(["authz", "--auth", auth_file]) == EXIT_OK
    out = capsys.readouterr().out
    assert "test engagement" in out
    assert "non-overridable denylist" in out


def test_authz_allows_an_in_scope_endpoint(auth_file, capsys):
    assert main(["authz", "--auth", auth_file, "--target", "mock:balanced"]) == EXIT_OK
    assert "ALLOW" in capsys.readouterr().out


def test_authz_denies_an_out_of_scope_endpoint(auth_file, capsys):
    assert (
        main(["authz", "--auth", auth_file, "--target", "https://api.example.com/v1"])
        == EXIT_USAGE
    )
    assert "DENY" in capsys.readouterr().out


def test_authz_denies_a_denylisted_endpoint(tmp_path, authorization_record, capsys):
    authorization_record["scope"]["targets"].append("https://blocked.example.com/*")
    authorization_record["scope"]["deny"] = ["blocked.example.com"]
    auth_path = tmp_path / "authorization.json"
    auth_path.write_text(json.dumps(authorization_record), encoding="utf-8")
    assert (
        main(
            [
                "authz",
                "--auth",
                str(auth_path),
                "--target",
                "https://blocked.example.com/x",
            ]
        )
        == EXIT_USAGE
    )
    out = capsys.readouterr().out
    assert "DENY" in out
    assert "denied" in out


def test_authz_reports_an_expired_record(tmp_path, authorization_record, capsys):
    authorization_record["expires"] = "2000-01-01"
    path = tmp_path / "expired.json"
    path.write_text(json.dumps(authorization_record), encoding="utf-8")
    assert main(["authz", "--auth", str(path)]) == EXIT_USAGE
    assert "EXPIRED" in capsys.readouterr().out


def test_authz_as_json(auth_file, capsys):
    assert main(["authz", "--auth", auth_file, "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["record"]["reference"] == "TEST-1"
    assert payload["expired"] is False
    assert payload["denylist"] == []


def test_authz_without_a_file_shows_the_offline_record(capsys):
    assert main(["authz"]) == EXIT_OK
    assert "offline self-test" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #
def test_init_scaffolds_both_files(tmp_path, capsys):
    assert main(["init", str(tmp_path)]) == EXIT_OK
    assert (tmp_path / "redteam.config.json").is_file()
    assert (tmp_path / "authorization.json").is_file()
    assert "Next steps" in capsys.readouterr().out


def test_scaffolded_authorization_does_not_run_until_a_human_signs_it(tmp_path):
    """The acknowledgements ship false on purpose."""
    from redteam.core.errors import ConfigError
    from redteam.policy.authorization import Authorization

    main(["init", str(tmp_path)])
    with pytest.raises(ConfigError, match="acknowledgements"):
        Authorization.load(tmp_path / "authorization.json")


def test_scaffolded_config_is_loadable(tmp_path):
    from redteam.core.config import RunConfig

    main(["init", str(tmp_path)])
    config = RunConfig.load(tmp_path / "redteam.config.json")
    assert config.targets
    assert config.probes


def test_init_does_not_clobber_without_force(tmp_path, capsys):
    main(["init", str(tmp_path)])
    (tmp_path / "authorization.json").write_text("CUSTOM", encoding="utf-8")
    capsys.readouterr()
    main(["init", str(tmp_path)])
    assert (tmp_path / "authorization.json").read_text(encoding="utf-8") == "CUSTOM"
    assert "skip" in capsys.readouterr().out


def test_init_force_overwrites(tmp_path):
    main(["init", str(tmp_path)])
    (tmp_path / "authorization.json").write_text("CUSTOM", encoding="utf-8")
    main(["init", str(tmp_path), "--force"])
    assert (tmp_path / "authorization.json").read_text(encoding="utf-8") != "CUSTOM"


# --------------------------------------------------------------------------- #
# probe_options
# --------------------------------------------------------------------------- #
def test_probe_options_from_the_config_reach_the_probe(tmp_path, capsys):
    """`corpus.custom` needs a path and may need detector overrides; the config has
    to be able to supply both, or the corpus path is CLI-only."""
    corpus = tmp_path / "corpus.local.jsonl"
    corpus.write_text(
        '{"id": "e1", "prompt": "x", "sentinel": "RT-CANARY-TEST01", '
        '"detectors": ["marker.echo", "refusal.heuristic"]}\n',
        encoding="utf-8",
    )
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "seed": "corpus-test",
                "targets": [{"id": "m", "plugin": "mock.llm", "options": {"profile": "hardened"}}],
                "probes": ["corpus.custom"],
                "probe_options": {"corpus.custom": {"path": str(corpus)}},
                "requests_per_minute": 0,
                "output_dir": str(tmp_path / "runs"),
                "formats": ["json"],
            }
        ),
        encoding="utf-8",
    )
    assert main(["run", "--config", str(config), "--quiet"]) == EXIT_OK


def test_judge_without_a_target_says_where_to_configure_it(tmp_path, capsys):
    """Corpus entries default to judge.llm. Failing loudly beats silently
    substituting a refusal lexicon for a category judgement."""
    corpus = tmp_path / "corpus.local.jsonl"
    corpus.write_text('{"id": "e1", "prompt": "x"}\n', encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "targets": [{"id": "m", "plugin": "mock.llm"}],
                "probes": ["corpus.custom"],
                "requests_per_minute": 0,
            }
        ),
        encoding="utf-8",
    )
    assert main(["plan", "--config", str(config), "--corpus", str(corpus)]) == EXIT_USAGE
    err = capsys.readouterr().err
    assert "detector_options" in err
    assert "authorization scope" in err


# --------------------------------------------------------------------------- #
# corpus import
# --------------------------------------------------------------------------- #
def _write_log(path, name, payload):
    target = path / name
    target.write_text(json.dumps(payload), encoding="utf-8")
    return str(target)


CONVERSATION = {
    "messages": [
        {"role": "user", "content": "first captured turn"},
        {"role": "assistant", "content": "first captured reply"},
    ]
}


def test_corpus_import_writes_one_entry_per_conversation(tmp_path, capsys):
    source = _write_log(tmp_path, "log.json", [CONVERSATION, CONVERSATION])
    out = tmp_path / "corpus.local.jsonl"
    assert (
        main(["corpus", "import", source, "--out", str(out), "--objective", "probe"])
        == EXIT_OK
    )
    entries = [json.loads(line) for line in out.read_text().splitlines()]
    assert [e["id"] for e in entries] == ["imported-0001", "imported-0002"]
    assert all(e["objective"] == "probe" for e in entries)
    assert all(
        e["detectors"]
        == ["judge.llm", "refusal.heuristic", "compliance.hedged"]
        for e in entries
    )
    assert entries[0]["messages"] == CONVERSATION["messages"]


def test_corpus_import_accepts_a_single_conversation_object(tmp_path):
    source = _write_log(tmp_path, "log.json", CONVERSATION)
    out = tmp_path / "corpus.local.jsonl"
    assert main(["corpus", "import", source, "--out", str(out)]) == EXIT_OK
    assert len(out.read_text().splitlines()) == 1


def test_corpus_import_accepts_jsonl(tmp_path):
    source = tmp_path / "log.jsonl"
    source.write_text(json.dumps(CONVERSATION) + "\n" + json.dumps(CONVERSATION) + "\n")
    out = tmp_path / "corpus.local.jsonl"
    assert main(["corpus", "import", str(source), "--out", str(out)]) == EXIT_OK
    assert len(out.read_text().splitlines()) == 2


def test_corpus_import_refuses_a_trackable_output_name(tmp_path):
    source = _write_log(tmp_path, "log.json", CONVERSATION)
    out = tmp_path / "corpus.jsonl"
    assert main(["corpus", "import", source, "--out", str(out)]) == EXIT_USAGE
    assert not out.exists()


def test_corpus_import_refuses_to_overwrite_without_force(tmp_path):
    source = _write_log(tmp_path, "log.json", CONVERSATION)
    out = tmp_path / "corpus.local.jsonl"
    assert main(["corpus", "import", source, "--out", str(out)]) == EXIT_OK
    assert main(["corpus", "import", source, "--out", str(out)]) == EXIT_USAGE
    assert main(["corpus", "import", source, "--out", str(out), "--force"]) == EXIT_OK
    lines = out.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["id"] == "imported-0002"


def test_corpus_import_aborts_on_credential_hits_and_values_are_not_written(tmp_path):
    source = _write_log(
        tmp_path, "log.json",
        {"messages": [{"role": "user", "content": "reach me at bob@example.org please"}]},
    )
    out = tmp_path / "corpus.local.jsonl"
    assert main(["corpus", "import", source, "--out", str(out)]) == EXIT_USAGE
    assert not out.exists()


def test_corpus_import_redaction_writes_placeholder_not_value(tmp_path):
    source = _write_log(
        tmp_path, "log.json",
        {"messages": [{"role": "user", "content": "reach me at bob@example.org please"}]},
    )
    out = tmp_path / "corpus.local.jsonl"
    assert main(["corpus", "import", source, "--out", str(out), "--redact"]) == EXIT_OK
    text = out.read_text()
    assert "bob@example.org" not in text
    assert "[REDACTED:email]" in text


def test_corpus_import_records_seeded_and_tags(tmp_path):
    source = _write_log(tmp_path, "log.json", CONVERSATION)
    out = tmp_path / "corpus.local.jsonl"
    assert (
        main(
            ["corpus", "import", source, "--out", str(out),
             "--seeded", "platform names only", "--tags", "category:test,from-log"]
        )
        == EXIT_OK
    )
    entry = json.loads(out.read_text().splitlines()[0])
    assert entry["seeded"] == "platform names only"
    assert entry["tags"] == ["category:test", "from-log"]


def test_corpus_import_applies_a_structured_rubric_to_every_entry(tmp_path):
    source = _write_log(tmp_path, "log.json", [CONVERSATION, CONVERSATION])
    rubric = tmp_path / "rubric.json"
    rubric.write_text(
        json.dumps(
            [
                {"id": "precursors", "description": "names plausible precursors"},
                {"id": "route", "description": "describes a coherent sequence"},
            ]
        ),
        encoding="utf-8",
    )
    out = tmp_path / "corpus.local.jsonl"
    assert (
        main(["corpus", "import", source, "--out", str(out), "--rubric", str(rubric)])
        == EXIT_OK
    )
    entries = [json.loads(line) for line in out.read_text().splitlines()]
    assert all(e["rubric"][1]["id"] == "route" for e in entries)


def test_corpus_import_rejects_a_malformed_rubric_file(tmp_path):
    source = _write_log(tmp_path, "log.json", CONVERSATION)
    rubric = tmp_path / "rubric.json"
    rubric.write_text('[{"id": "missing-description"}]', encoding="utf-8")
    out = tmp_path / "corpus.local.jsonl"
    assert (
        main(["corpus", "import", source, "--out", str(out), "--rubric", str(rubric)])
        == EXIT_USAGE
    )
    assert not out.exists()
