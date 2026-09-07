<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# docs

## Purpose
Prose documentation for operators and contributors: how the framework is put
together, how the authorization gate works, how to add extension points, the probe
catalog, and the safety model.

## Key Files
| File | Description |
|------|-------------|
| `ARCHITECTURE.md` | Six extension points, one gate, and the plan/execute split |
| `AUTHORIZATION.md` | The authorization record and how every contacted target is covered |
| `EXTENDING.md` | Registering a new probe/transform/detector/target/orchestrator/reporter |
| `PROBES.md` | Reference for the probes across eleven families, mapped to OWASP LLM Top 10 / MITRE ATLAS / EAA |
| `SAFETY.md` | The safety model: adversarial traffic, redaction, sentinels, embargo |

## For AI Agents

### Working In This Directory
- Keep these in sync with code. Adding an extension point or probe means updating
  `EXTENDING.md` / `PROBES.md`; changing the gate means updating `AUTHORIZATION.md`
  and `SAFETY.md`.
- Do not add harmful procedural content or real payloads to any doc.

### Testing Requirements
- No automated tests here, but probe counts and family names cited in `PROBES.md`
  should match what `redteam list` reports.

### Common Patterns
- Documentation cross-references the numbered operator instruction that every probe
  attacks.

## Dependencies

### Internal
- Describes the `redteam/` package.

<!-- MANUAL: -->
