<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# reporting

## Purpose
Artifacts for humans, machines, and CI. A reporter renders a `RunResult` (plus its
metrics) into a chosen format, passing everything through the redaction boundary
first so nothing sensitive reaches disk.

## Key Files
| File | Description |
|------|-------------|
| `base.py` | `Reporter` interface, `ReportOptions`, the `clean` redaction boundary, `risk_badge` |
| `__init__.py` | Registry glue: `build_reporter`, `render`, `write_reports` |
| `formats.py` | The formats: `ConsoleReporter`, `JsonReporter`, `JsonlReporter`, `MarkdownReporter`, `HtmlReporter`, `SarifReporter`, plus remediation and rate-table helpers |

## For AI Agents

### Working In This Directory
- **Everything written to disk goes through `clean`/redaction first.** Never emit a
  raw response, payload, or judge output without passing it through the redaction
  boundary — this is a safety invariant.
- Add a format by subclassing `Reporter` and registering it; reuse `_rate_table_rows`
  and `_remediation_for` for consistency.
- `SarifReporter` targets CI code-scanning; keep its schema valid.

### Testing Requirements
- `uv run pytest tests/framework/test_reporting.py`.

### Common Patterns
- Findings carry a risk badge and a remediation pointer that names the rule that broke.

## Dependencies

### Internal
- `core/` (redaction, findings), `scoring/` (metrics feeding the tables).

<!-- MANUAL: -->
