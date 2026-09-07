<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# dspy

## Purpose
Optional DSPy integrations, packaged so the core never needs them. Registers a
target (`dspy.stub`), an orchestrator (`dspy.redteamer`), and a detector
(`judge.dspy`) into the same six registries every other plugin uses. Importing
`redteam` loads only the stdlib registration modules; the `dspy` library itself is
imported lazily, and only through `require_dspy()`, which raises `ConfigError`
naming the `ai-redteam[dspy]` extra when it is absent. `redteam compile` (CLI) uses
this subpackage to optimize the program and write its artifact.

## Key Files
| File | Description |
|------|-------------|
| `__init__.py` | Registration staging: imports `stub`, `orchestrator`, `judge` — all stdlib-only at module scope |
| `bridge.py` | `require_dspy()` and `TargetBackedLM`, the typed `dspy.BaseLM` that forwards every model request to an injected send callable (the `send_once` seam) |
| `stub.py` | `dspy.stub` — offline deterministic attack-model simulator, endpoint `mock:dspy-stub`; imports no dspy |
| `program.py` | `Attack`/`Refine` signatures and the layered `AttackProgram`; imports dspy at module top, so only ever imported behind `require_dspy()` |
| `orchestrator.py` | `dspy.redteamer` — budgeted Attack/Refine execution, carrier-preserving, sentinel-drop becomes `INCONCLUSIVE` |
| `judge.py` | `judge.dspy` — `LlmJudge` subclass with a typed `dspy.ChainOfThought` verdict |
| `compile.py` | Gated MIPROv2 optimization writing the redacted, versioned `redteam.dspy.program.v1` artifact |

## For AI Agents

### Working In This Directory
- **Standard library at module scope; dspy via `require_dspy()` only.** Nothing here
  may import dspy at module level except `program.py`, which must only ever be
  imported from behind a `require_dspy()` call. `import redteam` must leave `dspy`
  out of `sys.modules` (asserted by `test_dspy_import_safety.py`).
- **THE INERT-OBJECTIVE RULE.** Generative optimization runs only on payloads that
  planted a sentinel and came from a registered probe. `corpus.custom` entries
  execute un-reframed, even when they carry an operator sentinel, because the probe
  id is what excludes them. Relaxing this is a deliberate owner act requiring a
  safety-model review, not a config flag.
- Every request role crosses `Orchestrator.send_once`; never add a second network
  path or a `build_target` call site. Side models are declared via
  `auxiliary_targets()` and authorized in `prepare_run` like any target.
- **Commit discipline for artifacts:** compiled program states are redacted,
  LM-free JSON. Every serialized `lm` entry is set to `null`, never deleted (the
  loader requires the key), string leaves pass through the redactor, and a write
  containing an endpoint or a custom LM class path is refused. The bridge LM is
  never serialized; a load supplies the LM via `dspy.context`, never from the
  artifact.

### Testing Requirements
- `uv run pytest tests/framework/test_dspy_bridge.py tests/framework/test_dspy_import_safety.py tests/framework/test_dspy_program.py tests/framework/test_dspy_orchestrator.py tests/framework/test_dspy_judge.py tests/framework/test_compile.py`
- dspy-dependent suites gate on `pytest.importorskip("dspy")` so the
  zero-dependency leg stays green.

## Dependencies

### Internal
- `orchestrators/base.py` (the `send_once` seam and the auxiliary-targets hook),
  `core/` (data model, errors, redaction), `detectors/judge.py` (`LlmJudge`),
  `targets/base.py` (the target registry), `policy/authorization.py`.

### External
- Standard library only at module scope. `dspy` (the optional extra, `>=3.3.1,<4`)
  is loaded lazily via `require_dspy()`; optuna arrives through `dspy[optuna]` for
  compile.

<!-- MANUAL: -->
