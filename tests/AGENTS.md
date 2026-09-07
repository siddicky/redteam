<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# tests

## Purpose
pytest suites covering two distinct concerns: the framework code (`framework/`) and
the integrity of the research-data archive under `data/` (`datacheck/`). Both
include a `test_safety_invariants.py` that guards the framework's safety properties.

## Key Files
| File | Description |
|------|-------------|
| `conftest.py` | Shared fixtures and pytest configuration |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `framework/` | Unit/behavior tests for the `redteam` package (see `framework/AGENTS.md`) |
| `datacheck/` | Tests validating the `data/` research files (see `datacheck/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Any change to framework behavior should come with a matching test in `framework/`.
- Do not weaken or `skip` the safety-invariant tests — they encode non-negotiable
  properties (the single pinned runtime dependency, authorization gate, redaction,
  sentinels).

### Testing Requirements
- Run with `uv run pytest` (or `make test`); `pythonpath = ["."]` makes `redteam`
  importable without installation. `testpaths` is set to `tests`.

### Common Patterns
- Tests are standard-library + pytest only; the pinned `grayswan-scraper` dependency
  is never imported by the suites.

## Dependencies

### Internal
- Imports `redteam` and the `data/` archive.

### External
- `pytest` (dev group).

<!-- MANUAL: -->
