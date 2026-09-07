<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-30 | Updated: 2026-08-30 -->

# probes

## Purpose
The attack-technique library. Each probe generates payloads that attack the same
numbered operator instruction, across eleven families cross-referenced to the OWASP
LLM Top 10, MITRE ATLAS, and the endpoint-AI-agent-abuse (EAA) taxonomy. Probes
describe *techniques*, not harmful content — harm-category evaluation runs on
operator-supplied corpora via `corpus.py`.

## Key Files
| File | Description |
|------|-------------|
| `base.py` | `Probe`/`TemplateProbe` interface, `ProbeContext`, `Variant`, and the operator instruction under attack |
| `__init__.py` | Registry glue: `build_probe`, `select_probes`, `generate_payloads` |
| `direct.py` | Direct injection in the user turn (override, refusal suppression, prefix, context termination) |
| `indirect.py` | Indirect injection via retrieved data — seven carriers (`document`, `webpage`, `tool_output`, `code`, `email`, `issue`, `pasted`) |
| `framing.py` | Social framing / obfuscation (persona, fiction, authority chain, many-shot, encoded, character smuggling) |
| `intent.py` | Intent-violation reframing (constraint substitution, multi-object confusion, UI reinterpretation) |
| `leakage.py` | System-prompt, conversation-history, and tool-inventory leakage |
| `agency.py` | Excessive agency: destructive action, privilege escalation, unauthorized recipient |
| `exfiltration.py` | Data exfiltration through rendered output (markdown-image, conversation relay) |
| `mcp.py` | MCP / tool-definition abuse (tool poisoning, config redirect) |
| `multiturn.py` | Multi-turn escalation (`Crescendo`, `Ladder`) |
| `output_handling.py` | Insecure output handling (unsafe markup, command syntax) as a downstream injection vector |
| `corpus.py` | Operator-supplied `CustomCorpus` probe and rubric validation |

## For AI Agents

### Working In This Directory
- Add a probe by subclassing `Probe`/`TemplateProbe` and registering it; keep it in
  the family file that matches its technique. Update `docs/PROBES.md` and its taxonomy
  mapping.
- Probes emit techniques against the operator instruction — do not embed real
  harmful payloads. The `corpus` probe is the only path for operator content, and it
  substitutes sentinels for harmful output.
- Keep payload generation deterministic via the seeded RNG from `core.util`.

### Testing Requirements
- `uv run pytest tests/framework/test_probes.py` and `test_mcp_intent_probes.py`.

### Common Patterns
- Probes yield `Payload`s; carriers/families are enumerated (`Carrier`, `Family` in
  `indirect.py`) so reporting can group by them.

## Dependencies

### Internal
- `core/` (data model, RNG), `transforms/` (payloads are mutated downstream).

<!-- MANUAL: -->
