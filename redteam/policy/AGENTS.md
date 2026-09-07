<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# policy

## Purpose
The authorization gate — the framework's primary safety interlock. Every live target
the framework contacts must be covered by an `Authorization` record whose `Scope`
matches the endpoint and whose window is current. Offline endpoints (the `mock` and
`replay` simulators) are recognized as such and exempted.

## Key Files
| File | Description |
|------|-------------|
| `authorization.py` | `Authorization`, `Scope`, endpoint/host matching, date-window parsing, and `is_offline_endpoint` |
| `__init__.py` | Rules of engagement, expressed as code |

## For AI Agents

### Working In This Directory
- **This is the most safety-critical code in the repo.** Do not loosen matching,
  widen scope, or skip the window/date check. A live call without a matching, current
  authorization must raise `AuthorizationError` and never reach the target.
- `is_offline_endpoint` is the only sanctioned bypass, and only for the offline
  simulators — keep its definition tight.
- Host/endpoint matching should fail closed on ambiguity.

### Testing Requirements
- `uv run pytest tests/framework/test_authorization.py` and the safety-invariant
  tests. Add cases for any change to matching or window logic.

### Common Patterns
- The CLI loads an authorization record (`redteam authz`) and the orchestrator checks
  every target against it before execution.

## Dependencies

### Internal
- `core/` (errors, config). Consulted by `targets/` and the orchestrators before any
  live call.

<!-- MANUAL: -->
