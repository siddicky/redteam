<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# redteam

## Purpose
The framework package. Turns a run configuration into a plan, executes the plan
against authorized targets, judges each response, and renders reports. Six pluggable
extension points — probes, transforms, detectors, targets, orchestrators, reporters —
are wired together through the `core` data model, config, and registries, behind the
`policy` authorization gate.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Package entry; version and top-level exports |
| `__main__.py` | `python -m redteam` entry point |
| `cli.py` | The command-line interface: `run`, `plan`, `list`, `report`, `compare`, `scan`, `authz`, `corpus`, `validate`, `init` |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `core/` | Data model, registries, config, and safety utilities (see `core/AGENTS.md`) |
| `probes/` | The attack-technique library, across eleven families (see `probes/AGENTS.md`) |
| `transforms/` | Payload mutations applied across the corpus (see `transforms/AGENTS.md`) |
| `detectors/` | How a response is judged, including LLM-as-judge (see `detectors/AGENTS.md`) |
| `targets/` | Adapters for each kind of system under test (see `targets/AGENTS.md`) |
| `orchestrators/` | Run strategies: sweep, crescendo, adaptive (see `orchestrators/AGENTS.md`) |
| `scoring/` | Metrics, findings triage, and run comparison (see `scoring/AGENTS.md`) |
| `reporting/` | Console/JSON/JSONL/Markdown/HTML/SARIF output (see `reporting/AGENTS.md`) |
| `policy/` | The authorization gate — rules of engagement as code (see `policy/AGENTS.md`) |
| `datacheck/` | Validation of the research data under `data/` (see `datacheck/AGENTS.md`) |
| `dspy/` | Optional DSPy integrations: bridge, orchestrator, judge, compile (see `dspy/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- The CLI is the single user-facing surface; keep new capabilities reachable through
  a `cmd_*` handler in `cli.py` and wired in `build_parser`.
- Adding a probe/transform/detector/target/orchestrator/reporter means registering
  it in the relevant subpackage's registry — see `docs/EXTENDING.md`.
- Preserve the plan/execute split (`orchestrators/base.py`): building a plan must
  stay side-effect-free; only execution contacts targets.

### Testing Requirements
- `uv run pytest tests/framework` covers this package.
- Add or extend a test in `tests/framework/` for any behavior change.

### Common Patterns
- Registries live at subpackage `__init__` level with `build_*`/`select_*` helpers.
- The `core.result` data model (`AttemptResult`, `RunResult`, `Verdict`) is the
  common currency passed between stages.

## Dependencies

### Internal
- `core/` underpins every other subpackage.

### External
- Standard library only.

<!-- MANUAL: -->
