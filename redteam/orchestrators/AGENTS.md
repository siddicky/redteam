<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# orchestrators

## Purpose
Run strategies. An orchestrator turns a config into a `RunPlan` (probes × transforms
× targets), then executes the plan into a `RunResult`. This is where the strict
plan/execute split lives: planning is side-effect-free; only execution contacts
targets.

## Key Files
| File | Description |
|------|-------------|
| `base.py` | `PlannedAttempt`, `RunPlan`, `RunContext`, the `Orchestrator` interface, and `prepare_run`/`execute_run` |
| `__init__.py` | Registry glue for strategies |
| `strategies.py` | The three strategies: `SweepOrchestrator`, `CrescendoOrchestrator`, `AdaptiveOrchestrator` |

## For AI Agents

### Working In This Directory
- Keep planning pure: building a `RunPlan` must not send traffic. Only `execute_run`
  (and the orchestrator's execution path) may contact targets.
- Enforce the attempt `Budget` and rate limiting during execution.
- Add a strategy by subclassing `Orchestrator` and registering it.

### Testing Requirements
- `uv run pytest tests/framework/test_orchestrators.py`.

### Common Patterns
- `Sweep` runs the full cartesian product; `Crescendo` escalates multi-turn ladders;
  `Adaptive` prefers what has been working (`_prefer`).

## Dependencies

### Internal
- `core/` (data model, budget), `probes/`, `transforms/`, `targets/`, `detectors/`.

<!-- MANUAL: -->
