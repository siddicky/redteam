<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# data

## Purpose
A research-data archive: a best-effort, snapshot compilation of publicly exposed
Gray Swan Arena challenges and verified public writeups/walkthroughs, plus a field
kit for an active challenge. It links to potentially dual-use material but does not
reproduce jailbreak payloads or harmful procedural content. The `redteam/datacheck`
package treats these files as the framework's own supply chain and validates them.

## Key Files
| File | Description |
|------|-------------|
| `README.md` | The human-readable archive: challenge inventory, coverage notes, snapshot date |
| `arena_challenges.csv` | Machine-readable named-challenge catalog |
| `proving_ground_waves.csv` | Proving Ground wave inventory (with recorded gaps, not guesses) |
| `public_writeups_walkthroughs.csv` | Verified public resources per challenge |
| `ipi_july_2026_run_log.csv` | Manual testing run log for the historical IPI challenge |
| `hazard_hunt_q3_run_log.csv` | Blank 39-behavior run-log template for the active Hazard Hunt Q3 challenge |
| `ACTIVE_CHALLENGE_PLAYBOOK.md` | Field kit for the Indirect Prompt Injection July '26 challenge (historical) |
| `HAZARD_HUNT_PLAYBOOK.md` | Field kit for the active Hazard Hunt Q3 challenge |
| `CLAUDE_CODE_HANDOFF.md` | Handoff notes / file map |

## For AI Agents

### Working In This Directory
- These files have declarative schemas and ground-truth invariants in
  `redteam/datacheck/schema.py`; edits must keep the CSVs schema-valid (headers,
  row counts, uniqueness, sequential ids).
- Do not add harmful procedural content, secrets, PII, or unexpected files — the
  safety checks in `datacheck/checks.py` assert against exactly these.
- Recorded gaps (e.g. missing waves) are intentional; do not backfill them with
  guesses.

### Testing Requirements
- `uv run pytest tests/datacheck` validates every file here. Run it after any edit.
- `redteam validate` / `redteam scan` also exercise these checks from the CLI.

### Common Patterns
- CSV files are paired with `README.md` cross-references that the cross-file checks
  verify for consistency.

## Dependencies

### Internal
- Validated by `redteam/datacheck/` and `tests/datacheck/`.

<!-- MANUAL: -->
