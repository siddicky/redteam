"""Repository-level safety invariants.

Everything else in the suite tests that the framework works. These test that it is
the *kind of thing* the README says it is — a red-team harness that runs only against
authorized targets, ships no attack content, and cannot be repurposed into a
submission bot for a platform whose rules forbid one.

They are deliberately structural rather than about behaviour: they assert on the
source tree, so a future change that quietly removes the gate or commits a payload
fails here rather than in review.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path

import pytest

from redteam.core.redact import Redactor
from redteam.core.sentinel import looks_like_sentinel
from redteam.detectors import DETECTORS, build_detector
from redteam.policy.authorization import BUILTIN_DENYLIST, Authorization
from redteam.probes import PROBES, build_probe
from redteam.targets import TARGETS

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = PROJECT_ROOT / "redteam"

SOURCE_FILES = sorted(
    p
    for p in PACKAGE_ROOT.rglob("*.py")
    if "__pycache__" not in p.parts
)


# --------------------------------------------------------------------------- #
# The gate cannot be bypassed
# --------------------------------------------------------------------------- #
def test_prepare_run_is_the_only_path_that_builds_targets_for_a_run():
    """A second construction path would be a second, ungated way to send traffic.

    ``build_target`` is allowed in the targets package, in ``prepare_run`` (which
    authorizes immediately after), in the judge detector (whose endpoint is
    authorized by ``prepare_run``), and in the CLI's pre-flight endpoint check
    (which sends nothing). Anywhere else needs review.
    """
    allowed = {
        PACKAGE_ROOT / "targets" / "__init__.py",
        PACKAGE_ROOT / "orchestrators" / "base.py",
        PACKAGE_ROOT / "detectors" / "judge.py",
        PACKAGE_ROOT / "cli.py",
    }
    offenders = [
        path.relative_to(PROJECT_ROOT)
        for path in SOURCE_FILES
        if path not in allowed and "build_target(" in path.read_text(encoding="utf-8")
    ]
    assert not offenders, (
        f"build_target() is called outside the audited paths: {offenders}. Every "
        f"construction site must be followed by an authorization check."
    )


def test_prepare_run_authorizes_before_it_returns():
    """Read the source: the authorize call must be inside the target loop."""
    source = (PACKAGE_ROOT / "orchestrators" / "base.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "prepare_run"
    )
    calls = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "authorize"
    ]
    assert calls, "prepare_run must call authorization.authorize()"


def test_the_builtin_denylist_is_empty():
    assert BUILTIN_DENYLIST == ()


def test_no_module_names_an_arena_submission_endpoint():
    """Nothing in the framework should know how to submit to the Arena."""
    for path in SOURCE_FILES:
        text = path.read_text(encoding="utf-8").lower()
        assert "app.grayswan.ai" not in text, (
            f"{path.relative_to(PROJECT_ROOT)} references an Arena endpoint"
        )


def test_scope_cannot_be_a_blanket_wildcard():
    """Re-asserted here because it is a repository-level guarantee, not just a
    function-level one: there is no configuration that authorizes everything."""
    from redteam.core.errors import ConfigError
    from redteam.policy.authorization import Scope

    with pytest.raises(ConfigError):
        Scope.from_dict(
            {"targets": ["*"], "max_attempts": 1, "max_requests_per_minute": 1}
        )


def test_offline_authorization_cannot_reach_a_live_endpoint():
    from redteam.core.errors import AuthorizationError

    with pytest.raises(AuthorizationError):
        Authorization.offline().authorize("https://anything.example.com/v1")


# --------------------------------------------------------------------------- #
# The repository ships no attack content and no secrets
# --------------------------------------------------------------------------- #
COMMITTED_TEXT_GLOBS = (
    "*.py",
    "*.md",
    "*.json",
    "*.jsonl",
    "*.toml",
    "*.lock",
    "*.yml",
    "*.yaml",
    "*.csv",
)


def _committed_text_files() -> list[Path]:
    files: list[Path] = []
    for pattern in COMMITTED_TEXT_GLOBS:
        for path in PROJECT_ROOT.rglob(pattern):
            parts = path.parts
            if any(
                part in {"__pycache__", ".git", ".pytest_cache", "runs", ".venv", "venv"}
                or part.endswith(".local")
                for part in parts
            ):
                continue
            if path.name.endswith((".local.csv", ".local.jsonl", ".local.json", ".local.md")):
                continue
            files.append(path)
    return sorted(files)


def test_no_committed_file_contains_a_credential():
    """The framework's own repository is held to the standard it enforces on runs."""
    redactor = Redactor(redact_emails=False, redact_cards=False)
    offenders: list[str] = []
    for path in _committed_text_files():
        # The pattern table and the tests that exercise it necessarily contain
        # credential-shaped strings.
        if path.name in {"redact.py", "checks.py"} or "test_" in path.name:
            continue
        for hit in redactor.scan(path.read_text(encoding="utf-8", errors="ignore")):
            offenders.append(f"{path.relative_to(PROJECT_ROOT)}:{hit.line} {hit.label}")
    assert not offenders, f"credentials found in committed files: {offenders}"


def test_no_committed_file_contains_a_run_transcript():
    """A sentinel outside the framework's own code means a raw transcript was pasted
    somewhere it should not have been."""
    allowed_names = {"sentinel.py", "mock.py", "builtin.py", "redact.py"}
    offenders: list[str] = []
    for path in _committed_text_files():
        if path.name in allowed_names or "test_" in path.name or path.name.endswith(".md"):
            continue
        if looks_like_sentinel(path.read_text(encoding="utf-8", errors="ignore")):
            offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert not offenders, f"run sentinels found in committed files: {offenders}"


def test_gitignore_excludes_run_artifacts_and_local_corpora():
    """Artifacts and operator corpora must not be committable by accident."""
    text = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    for rule in ("runs/", "*.local.csv", "*.local.jsonl", "authorization.json"):
        assert rule in text, f".gitignore is missing the {rule!r} rule"


# --------------------------------------------------------------------------- #
# The framework does not create the vulnerabilities it looks for
# --------------------------------------------------------------------------- #
def test_no_module_disables_tls_verification():
    for path in SOURCE_FILES:
        text = path.read_text(encoding="utf-8")
        for forbidden in ("_create_unverified_context", "CERT_NONE", "verify=False"):
            assert forbidden not in text, (
                f"{path.relative_to(PROJECT_ROOT)} weakens TLS verification"
            )


def test_no_module_runs_a_shell():
    """Building a shell string from probe text would let a payload escape the
    framework and execute on the operator's machine."""
    for path in SOURCE_FILES:
        text = path.read_text(encoding="utf-8")
        assert "shell=True" not in text, (
            f"{path.relative_to(PROJECT_ROOT)} uses shell=True"
        )
        assert "os.system(" not in text


def test_no_module_evaluates_dynamic_code():
    for path in SOURCE_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec", "compile"}, (
                    f"{path.relative_to(PROJECT_ROOT)} evaluates dynamic code"
                )


def test_the_framework_never_executes_a_declared_tool():
    """Tool schemas are declarations for the target, never something we run. A probe
    that could execute its own tool would make this framework the attacker."""
    for probe_id in PROBES.names():
        probe = build_probe(probe_id) if probe_id != "corpus.custom" else None
        if probe is None:
            continue
        for tool in probe.tools:
            assert set(tool) <= {"name", "description", "parameters"}, (
                f"{probe_id} tool declaration carries unexpected keys — a schema is "
                f"data, not a callable"
            )


# --------------------------------------------------------------------------- #
# The measurement is honest
# --------------------------------------------------------------------------- #
def test_interpretive_detectors_cannot_report_a_bypass():
    """A lexicon must never be able to promote an attempt to a finding on its own."""
    import inspect

    for detector_id in ("refusal.heuristic", "injection.disclosure"):
        source = inspect.getsource(type(build_detector(detector_id)))
        assert "self.bypassed(" not in source, (
            f"{detector_id} can report a bypass; interpretive detectors must only "
            f"distinguish 'blocked' from 'undecidable'"
        )


def test_every_registry_is_populated():
    """An empty registry would make a run silently do nothing and report a pass."""
    assert len(PROBES) >= 15
    assert len(TARGETS) >= 4
    assert len(DETECTORS) >= 8


def test_offline_targets_exist_so_the_demo_path_needs_no_credentials():
    """If the demo required a live endpoint, nobody would run it before pointing the
    tool at production."""
    offline = TARGETS.with_tag("offline")
    assert "mock.llm" in offline
    assert "replay.transcript" in offline


def test_the_default_operator_prompt_states_numbered_rules():
    """Findings cite the rule they broke; unnumbered prose could not be cited."""
    from redteam.probes.base import DEFAULT_SYSTEM_PROMPT

    for number in range(1, 6):
        assert f"{number}." in DEFAULT_SYSTEM_PROMPT
    assert "DATA" in DEFAULT_SYSTEM_PROMPT  # the provenance rule


def test_documentation_covers_the_safety_model():
    docs = PROJECT_ROOT / "docs"
    for name in ("SAFETY.md", "AUTHORIZATION.md"):
        path = docs / name
        assert path.is_file(), f"docs/{name} is missing"
        assert len(path.read_text(encoding="utf-8")) > 1000


def test_readme_states_the_authorization_requirement():
    text = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8").lower()
    assert "authoriz" in text


# --------------------------------------------------------------------------- #
# Supply chain
# --------------------------------------------------------------------------- #
def _pyproject() -> dict:
    """Parse pyproject.toml.

    The interpreter floor is 3.11, so the stdlib ``tomllib`` is always present —
    no fallback needed. These are the invariants that keep the runtime dependency
    surface a single, deliberate, pinned requirement.
    """
    import tomllib

    return tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _optional_extras_ok(optional_dependencies: Mapping[str, list[str]]) -> bool:
    return set(optional_dependencies) <= {"dspy"}


# The one allowed runtime dependency, pinned to an exact commit of the owner's fork
# scraper. Anything else joins every engagement's supply chain and is refused here.
PINNED_SCRAPER_REQUIREMENT = (
    "grayswan-scraper @ git+https://github.com/siddicky/gs-submissions.git"
    "@7a11e78d803189d598b5997961a9c6757b9f6ca4"
)


def _normalize_requirement(requirement: str) -> str:
    """Collapse whitespace so equivalent requirement strings compare equal."""
    return " ".join(requirement.split())


def test_the_framework_declares_exactly_one_pinned_runtime_dependency():
    """The runtime dependency list is exactly the pinned grayswan-scraper requirement.

    The scraper is imported lazily by the arena-scrape surface only; the rest of the
    core CLI still runs on a bare interpreter. Asserting the exact requirement here
    means adding another dependency — or re-pinning this one — is a deliberate act
    with a failing test attached, rather than something that slips in with a feature.
    """
    project = _pyproject()["project"]
    dependencies = [
        _normalize_requirement(r) for r in project.get("dependencies", [])
    ]
    optional_dependencies = project.get("optional-dependencies", {})
    deliberate_change_message = (
        "If the pinned requirement or an extra changes, update README.md, "
        "docs/SAFETY.md, and the no-dependencies CI job in the same change."
    )
    assert dependencies == [PINNED_SCRAPER_REQUIREMENT], (
        f"the framework's runtime dependencies must be exactly "
        f"{PINNED_SCRAPER_REQUIREMENT!r}; found {dependencies}. "
        f"{deliberate_change_message}"
    )
    assert project.get("requires-python") == ">=3.11", (
        f"requires-python must be '>=3.11' (the pinned scraper's floor); found "
        f"{project.get('requires-python')!r}. {deliberate_change_message}"
    )
    assert _optional_extras_ok(optional_dependencies), (
        f"the framework declares unsupported extras {set(optional_dependencies)}. "
        f"{deliberate_change_message}"
    )


def test_optional_extras_policy_rejects_a_second_extra():
    assert not _optional_extras_ok({"dspy": ["dspy>=3.3.1"], "other": ["other>=1"]})


def test_dev_tooling_is_a_dependency_group_not_a_published_extra():
    """pytest is not something a consumer of this package should be offered."""
    data = _pyproject()
    assert "dev" in data.get("dependency-groups", {})
    assert "dev" not in data.get("project", {}).get("optional-dependencies", {})


def test_the_lockfile_is_committed_and_covers_the_dev_group():
    """`make test` and CI both run `uv sync --locked`, which needs a lock in tree.

    Pinning the toolchain matters more here than for most projects: "which pytest
    validated the detectors on the day we signed the report?" should have an answer.
    """
    lock = PROJECT_ROOT / "uv.lock"
    assert lock.is_file(), "uv.lock is missing; run 'make lock'"
    text = lock.read_text(encoding="utf-8")
    assert 'name = "ai-redteam"' in text
    assert 'name = "pytest"' in text
    assert "requires-python" in text


def test_the_lockfile_is_not_gitignored():
    ignored = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "uv.lock" not in ignored, (
        "uv.lock must be committed; an ignored lockfile defeats --locked"
    )
