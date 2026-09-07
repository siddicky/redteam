<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# core

## Purpose
Core primitives shared by every other subpackage: the data model, the plugin
registry, run configuration, the exception hierarchy, and the safety utilities
(redaction and sentinels). Everything else depends on `core`; `core` depends on
nothing but the standard library.

## Key Files
| File | Description |
|------|-------------|
| `result.py` | The data model: `Outcome`, `Risk`, `Message`, `TargetResponse`, `Payload`, `Verdict`, `AttemptResult`, `RunResult`, `aggregate_verdicts` |
| `findings.py` | `Severity`, `Finding`, `Report` primitives shared by every check |
| `registry.py` | The tiny plugin `Registry` (and `Entry`) behind all six extension points |
| `config.py` | `RunConfig` / `TargetConfig`, env expansion, optional TOML loading |
| `errors.py` | Exception hierarchy (`RedTeamError`, `AuthorizationError`, `PolicyViolation`, `BudgetExceeded`, ...) |
| `redact.py` | Credential/PII redaction (`Redactor`, `redact`, `scan`, `excerpt`) for anything written to disk |
| `sentinel.py` | `SentinelFactory` — harmless stand-ins substituted for harmful output |
| `codecs.py` | Low-level encodings (base64/hex/rot13/leet/zero-width/homoglyph) shared by transforms and the simulator |
| `ratelimit.py` | `RateLimiter`, `RetryPolicy`, `retry`, and the attempt `Budget` |
| `util.py` | Ids, timestamps, deterministic randomness (`rng_for`, `default_seed`, `slugify`) |

## For AI Agents

### Working In This Directory
- This is the foundation; changes ripple everywhere. Keep the data model and
  registry backward-compatible where possible.
- `redact.py` and `sentinel.py` are safety-critical. The redaction boundary and
  sentinel substitution must not be bypassed; both are covered by safety-invariant
  tests.
- Randomness flows through `util.rng_for` for determinism — do not introduce
  unseeded `random`/`os.urandom` in the run path.

### Testing Requirements
- `uv run pytest tests/framework/test_core.py` and the safety-invariant tests.

### Common Patterns
- `Registry` instances live in each subpackage's `__init__` and are populated by
  decorators; ids are stable strings used in config.

## Dependencies

### External
- Standard library only.

<!-- MANUAL: -->
