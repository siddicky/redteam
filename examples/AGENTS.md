<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# examples

## Purpose
Runnable configurations and templates. The offline demo is the recommended starting
point: three simulator profiles, no credentials, no network, no authorization record
required.

## Key Files
| File | Description |
|------|-------------|
| `offline-demo.config.json` | Three simulated targets (`hardened`, `balanced`, `agentic`). Start here |
| `live-target.config.json` | A realistic three-target engagement: raw model, application wrapper, local agent |
| `authorization.example.json` | A filled-in authorization record |
| `corpus.example.jsonl` | Template for the `corpus.custom` probe (harm-category evaluation with your own prompts) |
| `README.md` | Walkthrough of the demo and the simulator profiles |

## For AI Agents

### Working In This Directory
- The offline demo must keep running with zero setup — do not introduce a network
  call, credential, or authorization requirement into it.
- `corpus.example.jsonl` is a template only; do not populate it with real harmful
  content.

### Testing Requirements
- `uv run redteam run --config examples/offline-demo.config.json` should complete and
  produce findings. The `hardened` profile is expected to find nothing — that is the
  control that proves detectors are not always firing.

### Common Patterns
- Config files are JSON consumed by `redteam.core.config` (`RunConfig`).

## Dependencies

### Internal
- Exercised by `redteam.cli` and the `mock` target (`redteam/targets/mock.py`).

<!-- MANUAL: -->
