<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# datacheck

## Purpose
Validation of the research data under `data/` — treated as the framework's own supply
chain. Loads the CSV/markdown archive, checks each file against a declarative schema,
verifies cross-file consistency, and runs safety checks (no secrets, no PII, no
unexpected files, embargo notice present, gitignore correct). Surfaced through the CLI
as `redteam validate` / `redteam scan`.

## Key Files
| File | Description |
|------|-------------|
| `schema.py` | Declarative `CsvSchema`/`ColumnSpec` and ground-truth invariants for the research data |
| `validators.py` | Generic schema-driven validators (header, row count, no ragged rows, uniqueness, sequential ids) |
| `loaders.py` | Loading the data files: `Table`, `Dataset`, `load_dataset`, `default_data_dir` |
| `checks.py` | Concrete per-file, cross-file, and safety checks; `run_all` |
| `__init__.py` | Subpackage entry — "the framework's own supply chain" |

## For AI Agents

### Working In This Directory
- When `data/` files change, update the schema/invariants here in lockstep — the
  ground-truth counts and mappings are asserted, not inferred.
- The safety checks (`check_safety_secrets`, `check_safety_pii`,
  `check_safety_unexpected_files`, `check_safety_embargo_notice`, ...) are the guard
  against the archive leaking sensitive material; do not weaken them.
- Keep loaders standard-library CSV only (no pandas) to match the dependency stance.

### Testing Requirements
- `uv run pytest tests/datacheck` mirrors these checks per data file.

### Common Patterns
- `run_all` aggregates every check into a `Report` of `Finding`s, the same primitive
  the framework uses elsewhere.
- Recorded gaps in the data are intentional and asserted as gaps, not errors.

## Dependencies

### Internal
- `core/` (findings, config). Validates the `data/` archive.

<!-- MANUAL: -->
