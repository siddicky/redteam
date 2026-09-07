<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# .github

## Purpose
GitHub configuration — continuous integration for the framework. CI enforces the
project's core invariants on every push and pull request, not just the test suite.

## Key Files
| File | Description |
|------|-------------|
| `workflows/ci.yml` | The CI workflow. Jobs: `test` (pytest), `no-dependencies` (asserts the core CLI runs without the pinned dependency), `offline-demo` (runs the credential-free demo end-to-end), `safety-invariants` (runs the safety-invariant suites) |

## For AI Agents

### Working In This Directory
- The `no-dependencies` and `safety-invariants` jobs encode non-negotiable properties
  (install-free core CLI, authorization gate, redaction, sentinels). Do not relax
  or remove them.
- Keep the `offline-demo` job hermetic — it must run without credentials, network, or
  an authorization record.

### Testing Requirements
- Mirror CI locally with `make test` and
  `uv run redteam run --config examples/offline-demo.config.json` before pushing.

### Common Patterns
- Jobs run on the locked toolchain; the `no-dependencies` job proves the core CLI
  runs bare (the pinned `grayswan-scraper` dependency is arena-scrape-only).

## Dependencies

### External
- GitHub Actions runners, `uv`, `pytest`.

<!-- MANUAL: -->
