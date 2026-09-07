<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# targets

## Purpose
Adapters for each kind of system under test — one `Target` per kind. A target takes
a conversation and returns a `TargetResponse`. Live adapters (HTTP, subprocess) must
be covered by an authorization record; offline adapters (`mock`, `replay`) run
without one, which is what makes the offline demo possible.

## Key Files
| File | Description |
|------|-------------|
| `base.py` | The `Target` interface and `require_option` helper |
| `__init__.py` | Registry glue: `build_target` |
| `http.py` | HTTP adapters: `OpenAICompatTarget`, `AnthropicTarget`, and a templated `GenericHttpTarget` for the application in front of the model |
| `command.py` | `CommandTarget` — a local subprocess agent or CLI |
| `mock.py` | `MockTarget` — an offline guardrail simulator (profiles: hardened/balanced/agentic) |
| `replay.py` | `ReplayTarget` — re-serves responses from a saved run for offline re-analysis |

## For AI Agents

### Working In This Directory
- Add an adapter by subclassing `Target` and registering it. Any adapter that
  contacts a live endpoint must go through the authorization gate (`policy/`) — never
  add a network/subprocess path that bypasses it.
- `mock` and `replay` are the offline surface; keep them credential-free and
  deterministic so the demo and tests stay hermetic.
- Respect the rate limiter, retry policy, and attempt budget from `core/ratelimit.py`
  on live calls.

### Testing Requirements
- `uv run pytest tests/framework/test_targets.py`.

### Common Patterns
- Adapters read their settings from `TargetConfig` options via `require_option`.
- HTTP adapters normalize provider-specific request/response shapes into the shared
  `Message`/`ToolCall` model.

## Dependencies

### Internal
- `core/` (data model, config, ratelimit), `policy/` (authorization for live calls).

### External
- Standard library only (`urllib`, `subprocess`).

<!-- MANUAL: -->
