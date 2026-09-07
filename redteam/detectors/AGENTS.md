<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# detectors

## Purpose
How a target response is judged. A detector inspects an attempt's response (and its
tool calls) and emits a `Verdict` with a score and a human-readable reason. Detectors
compose, and an optional LLM-as-judge is available for cases heuristics cannot decide.

## Key Files
| File | Description |
|------|-------------|
| `base.py` | `Detector` interface, `DetectionContext`, `run_detectors` |
| `__init__.py` | Registry glue: `build_detector`, `build_detectors`, `close_detectors` |
| `builtin.py` | The built-in detectors: `MarkerEcho`, `CanaryLeak`, `ExfilUrlCanary`, `ForbiddenToolCall`, `UnsafeMarkup`, `RegexMatch`, `ComplianceHedged`, `RefusalHeuristic`, `InjectionDisclosure`, `CompositeAll`, `CompositeWeighted` |
| `judge.py` | `LlmJudge` — LLM-as-judge detector with JSON extraction and score clamping |

## For AI Agents

### Working In This Directory
- Add a detector by subclassing `Detector` and registering it; return a `Verdict`
  with a clamped score in `[0, 1]` and a specific reason string (reasons appear in
  findings).
- The judge in `judge.py` reaches out to an endpoint — it must be authorized like
  any other target and must never leak harmful content; keep its output redacted and
  sentinel-aware.
- Composite detectors (`CompositeAll`, `CompositeWeighted`) combine sub-detectors;
  prefer composing over duplicating logic.

### Testing Requirements
- `uv run pytest tests/framework/test_detectors.py` and `test_judge.py`.

### Common Patterns
- Detector ids are stable strings (e.g. `toolcall.forbidden`, `compliance.hedged`).
- `close_detectors` releases any resources (e.g. judge clients) after a run.

## Dependencies

### Internal
- `core/` (data model, verdict aggregation, redaction).
- The judge uses a `targets/` adapter to reach its endpoint.

<!-- MANUAL: -->
