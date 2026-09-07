<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# datacheck

## Purpose
Tests that validate the research-data archive under `data/`, mirroring the checks in
`redteam/datacheck`. They assert per-file schema conformance, cross-file consistency,
and the data safety invariants (no secrets, no PII, no unexpected files).

## Key Files
| File | Description |
|------|-------------|
| `test_safety_invariants.py` | Data-side safety guarantees for the archive |
| `test_arena_challenges.py` | `arena_challenges.csv` schema and inventory |
| `test_proving_ground_waves.py` | Wave inventory, including recorded gaps |
| `test_public_writeups.py` | `public_writeups_walkthroughs.csv` and challenge mapping |
| `test_run_log.py` | The IPI manual run log |
| `test_cross_file.py` | Consistency across README, CSVs, playbook, and handoff |
| `test_datacheck_cli.py` | The `validate`/`scan` CLI surface |
| `test_validator_selfcheck.py` | The generic validators validate themselves |

## For AI Agents

### Working In This Directory
- When `data/` changes, these must be updated together with the schemas in
  `redteam/datacheck/schema.py`.
- The safety-invariant test is the guard against the archive leaking sensitive
  material — keep it strict.

### Testing Requirements
- `uv run pytest tests/datacheck`.

### Common Patterns
- Tests load the archive through `redteam.datacheck.loaders` rather than reading CSVs
  directly.

## Dependencies

### Internal
- `redteam.datacheck`, the `data/` archive.

### External
- `pytest`.

<!-- MANUAL: -->
