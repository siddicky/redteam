<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# framework

## Purpose
Unit and behavior tests for the `redteam` package — one test module per subpackage,
plus a safety-invariant suite that encodes the framework's non-negotiable properties.

## Key Files
| File | Description |
|------|-------------|
| `test_safety_invariants.py` | Guards the safety properties: the single pinned runtime dependency, authorization gate, redaction boundary, sentinel substitution |
| `test_core.py` | Data model, registry, config, redaction, ratelimit |
| `test_authorization.py` | The authorization gate and scope/window matching |
| `test_probes.py` / `test_mcp_intent_probes.py` | Probe generation across families |
| `test_transforms.py` | Payload transforms |
| `test_detectors.py` / `test_judge.py` | Detectors and LLM-as-judge |
| `test_targets.py` | Target adapters (including offline mock/replay) |
| `test_orchestrators.py` | Plan/execute strategies |
| `test_scoring.py` | Metrics, dedup, comparison |
| `test_reporting.py` | Output formats and the redaction boundary |
| `test_cli.py` | CLI command surface |

## For AI Agents

### Working In This Directory
- A behavior change in `redteam/<subpackage>` should update the matching
  `test_<subpackage>.py`.
- Do not `skip`, `xfail`, or weaken `test_safety_invariants.py`; if it fails, fix the
  code, not the test.

### Testing Requirements
- `uv run pytest tests/framework`.

### Common Patterns
- Tests are hermetic — they use the offline `mock`/`replay` targets and the seeded
  RNG rather than live endpoints.

## Dependencies

### Internal
- Imports the `redteam` package.

### External
- `pytest`.

<!-- MANUAL: -->
