<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# scoring

## Purpose
Turns a pile of attempts into numbers someone can act on: attack-success rates
(overall and by carrier/transform), a resilience score, deduplicated top findings,
and comparison between two runs.

## Key Files
| File | Description |
|------|-------------|
| `metrics.py` | `Rate`, `Metrics`, `summarize`/`summarize_attempts`, `resilience_score`, `top_findings`, `deduplicate_findings`, `compare`, coverage warnings |
| `__init__.py` | Subpackage exports |

## For AI Agents

### Working In This Directory
- Metrics are derived purely from `RunResult`/`AttemptResult`; keep this subpackage
  free of I/O and target contact.
- `deduplicate_findings` and `top_findings` decide what surfaces in a report — changes
  here change triage; add tests for edge cases.
- `compare` supports regression tracking across runs; keep its output stable.

### Testing Requirements
- `uv run pytest tests/framework/test_scoring.py`.

### Common Patterns
- Rates are computed with a shared `_rates` helper and grouped by dimension (carrier,
  transform) for the reporter's tables.

## Dependencies

### Internal
- `core/` (data model, findings).

<!-- MANUAL: -->
