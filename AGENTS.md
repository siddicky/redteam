<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# ai_red_teaming

## Purpose
An automated red-teaming framework (`redteam`, distributed as `ai-redteam`) that
fires a corpus of attack techniques at an LLM or agent deployment you are
**authorized to test**, decides for each attempt whether the guardrail held, and
produces a report naming the rule that broke. Zero runtime dependencies — the core
CLI runs on a bare interpreter. Every live target must be covered by an
authorization record; the authorization gate (`redteam/policy`) is the primary
safety interlock. Offline targets (the `mock`/`replay` simulators) run without
authorization.

This documentation describes the framework's architecture. It intentionally does
**not** reproduce attack payloads, jailbreak content, or harmful procedural
material — those concerns live in the corpus data, not in code, and the code is
built to redact and sentinel-substitute such content on the way to disk.

## Key Files
| File | Description |
|------|-------------|
| `pyproject.toml` | Package metadata, `redteam` console script, zero runtime dependencies (enforced by a test), PEP 735 dev group |
| `Makefile` | Common developer entry points (`make test`, `make lint`) |
| `README.md` | User-facing overview: what it does, the offline demo, sample output |
| `uv.lock` | Committed lockfile — pins the dev toolchain for reproducible engagement runs |
| `redteam.config.json` | Local run configuration |
| `authorization.json` | Local authorization record (rules of engagement) |
| `*.local.json` / `*.local.jsonl` | Git-ignored local corpora, rubrics, and captured run artifacts |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `redteam/` | The framework package — probes, detectors, targets, orchestrators, scoring, reporting (see `redteam/AGENTS.md`) |
| `tests/` | pytest suites for the framework and the research data (see `tests/AGENTS.md`) |
| `docs/` | Architecture, authorization, extending, probe reference, safety model (see `docs/AGENTS.md`) |
| `examples/` | Runnable configs and templates, including the offline demo (see `examples/AGENTS.md`) |
| `data/` | Research-data archive (Arena challenges, writeups) validated by `datacheck` (see `data/AGENTS.md`) |
| `runs/` | Saved run artifacts (git-ignored operational output) |

## For AI Agents

### Working In This Directory
- **The runtime dependency list stays exactly empty.**
  `tests/framework/test_safety_invariants.py` asserts `dependencies` equals `[]`
  and `requires-python` stays `>=3.11`. The core CLI runs on a bare interpreter;
  add no runtime import or dependency without the same-commit protocol
  (entry in `uv.lock`, pyproject policy comment, README, docs/SAFETY.md, CI job,
  this policy). Dev-only tooling goes in the `dev` dependency group.
- Never weaken the authorization gate, the redaction boundary, or the sentinel
  substitution. These are safety invariants covered by dedicated tests
  (`test_safety_invariants.py` in both test suites).
- Do not add real harmful payloads or procedural content anywhere. Harm-category
  probes operate on operator-supplied corpora and substitute sentinels for output.
- Use `uv` to run and manage the project (`uv run redteam ...`, `uv sync`).

### Testing Requirements
- `make test` (or `uv run pytest`) — `pyproject.toml` sets `pythonpath = ["."]` so
  `import redteam` works without an install.
- `make lint` runs `ruff check`.
- The offline demo (`uv run redteam run --config examples/offline-demo.config.json`)
  is a fast end-to-end smoke check needing no credentials or authorization.

### Common Patterns
- Six extension points, each a `core.registry.Registry`: probes, transforms,
  detectors, targets, orchestrators, reporters. Register with a decorator; ids are
  stable strings.
- Strict plan/execute split: a config becomes a `RunPlan`, then the plan is executed.
- The `.local.*` suffix marks git-ignored engagement-specific files.

## Dependencies

### External
- Zero runtime dependencies: the core CLI runs on the standard library alone, and
  `tests/framework/test_safety_invariants.py` enforces the empty list.
- `pytest` (dev group) — test runner.
- `ruff` — linting.
- `uv` — environment and reproducibility.

<!-- MANUAL: Custom project notes can be added below -->
