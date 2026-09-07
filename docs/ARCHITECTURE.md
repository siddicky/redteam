# Architecture

Six extension points, one gate, and a strict plan/execute split. This page explains
why the pieces are divided the way they are — the divisions are the design, and most
of them exist because the obvious alternative produces reports nobody can act on.

---

## The shape

```
                        ┌──────────────────────────────────────┐
   redteam.config.json  │  RunConfig                           │
   authorization.json   │  Authorization  ── the gate ──┐      │
                        └───────────────────────────────┼──────┘
                                                        │
                                     prepare_run() ─────┤ authorize(endpoint)
                                          │             │ for every target AND
                                          │             │ every judge detector
                                          ▼             │
                        ┌──────────────────────────────────────┐
                        │  RunPlan                             │  ← printable,
                        │  every attempt, incl. skips + reasons│    deterministic,
                        └──────────────────────────────────────┘    sends nothing
                                          │
                                execute_run()
                                          │
   ┌──────────┐   Payload   ┌─────────┐  TargetResponse   ┌───────────┐  Verdict
   │  Probe   │────────────▶│ Target  │──────────────────▶│ Detector  │────────┐
   └──────────┘             └─────────┘                   └───────────┘        │
        │  ▲                                                                   │
   Transform│                                                                  ▼
        └───┘                                              ┌──────────────────────┐
                                                           │  AttemptResult       │
                                                           │  → RunResult         │
                                                           └──────────────────────┘
                                                                       │
                                        Metrics ◀──────────────────────┤
                                        Reporter ◀─────────────────────┘
                                        (console/json/jsonl/md/html/sarif)
```

## Package layout

```
redteam/
  core/               data model, registries, config, redaction, codecs
    result.py         Message, Payload, Verdict, AttemptResult, RunResult, Risk
    registry.py       the plugin registry every extension point uses
    config.py         RunConfig, TargetConfig, ${env:VAR} interpolation
    redact.py         credential/PII patterns — shared with datacheck
    sentinel.py       deterministic inert markers
    codecs.py         encodings, shared by transforms and the simulator
    ratelimit.py      token bucket, retry policy, attempt budget
  policy/
    authorization.py  the gate: default deny, denylist, ceilings, expiry
  targets/            systems under test        (6 adapters)
  probes/             attack techniques         (35 probes)
  transforms/         payload mutations         (13 transforms)
  detectors/          verdicts                  (12 detectors)
  orchestrators/      run strategies            (sweep, crescendo, adaptive)
  reporting/          artifacts                 (6 formats)
  scoring/            metrics, triage, run comparison
  datacheck/          research-data validation (the probe corpus's own supply chain)
  dspy/               optional DSPy integrations (lazy satellite; see below)
  cli.py              plan | run | compile | list | report | compare | scan | authz | validate | init

pyproject.toml        empty project.dependencies, the single optional `dspy` extra,
                      and a PEP 735 `dev` group
uv.lock               committed: the dev toolchain is pinned, not "whatever resolved"
.python-version       the interpreter uv picks locally; CI covers 3.10–3.13
```

### The dependency-free core is enforced, not asserted

`project.dependencies` is empty and stays that way:
`tests/framework/test_safety_invariants.py` fails if it grows, and a CI job runs the
whole CLI under `uv run --no-project --isolated` — an environment with nothing
installed at all — so a stray third-party import breaks the build rather than
quietly joining every engagement's supply chain.

The *dev* toolchain is the opposite: locked hard. For a tool whose output lands in a
report, "which pytest validated the detectors on the day we signed it?" should have
an answer, so `uv.lock` is committed and both `make test` and CI use `--locked`,
which fails on a stale lockfile rather than silently resolving something new.

## The DSPy satellite

`redteam/dspy/` is a lazy satellite of the six registries, not an eighth extension
point: importing `redteam` runs its three stdlib-only registration modules, so
`dspy.stub`, `dspy.redteamer`, and `judge.dspy` appear in the same registries as
everything else while `dspy` itself stays out of `sys.modules`, and the library is
loaded only when a plugin calls `require_dspy()`. Every request role it introduces
(the attack model, the refine loop, the compile-time optimizer, and the judge's own
model) crosses the same audited `send_once` seam under the same ceilings, with
side-model endpoints authorized in `prepare_run` like any target, and the trained
programs `redteam compile` produces are redacted, LM-free JSON artifacts under
`runs/`.

---

## Why plan and execute are separate

`prepare_run` computes a `RunPlan` with no network access. It is fully deterministic
from the run seed and it is printable, so `redteam plan` shows an operator exactly
what would be sent, to which endpoints, how many requests that is, and which
attempts would be skipped and why.

Approving a red-team run should not require running it. That is the whole
justification, and it is why the plan reports a *true* request count — including the
per-rung cost of multi-turn attempts, which a naive one-attempt-one-request count
understates fourfold.

`execute_run` then walks the plan under three ceilings, all derived from the
authorization record rather than the config.

## Why the gate lives in `prepare_run`

It is the single place where a target is constructed and a request becomes possible.
Authorizing anywhere later would leave a window; authorizing in the CLI would leave
the library path open.

`tests/framework/test_safety_invariants.py` asserts structurally that
`build_target()` appears only in audited files, so a second construction path cannot
be added without failing the suite.

---

## The data model

Everything that flows between extension points is a frozen dataclass that
round-trips through JSON. That property is what makes a saved run an **input**
rather than a log: `redteam report` re-renders it, and the `replay.transcript`
target re-serves it, so detectors can be re-scored offline without spending another
round of traffic against someone's production system.

Two vocabularies are kept apart deliberately:

- **`Severity`** (`error`/`warning`/`info`) describes problems with *our own* data
  and configuration.
- **`Risk`** (`critical`…`info`) describes how bad it is that a *target* failed a
  probe.

And `AttemptResult.risk` returns the payload's risk **only when the attempt actually
bypassed**. A blocked critical probe is not a critical finding.

### Provenance is structural

`Message.trusted` marks the turns that carry attacker-controlled content. This is not
decoration:

- Transforms mutate only untrusted turns — mutating the system prompt or the
  legitimate task would change *what* is asked rather than *how it is encoded*, and
  the comparison against the baseline would mean nothing.
- The report can say which channel carried the attack, which is the dimension that
  matters for prompt-injection triage.
- The offline simulator infers its carrier from it.

---

## Verdict aggregation

`aggregate_verdicts` has precedence `BYPASSED` > `BLOCKED` > `ERROR` (only when
*every* detector errored) > `INCONCLUSIVE`. Two asymmetries, both load-bearing.

**One bypass beats any number of blocks.** A guardrail that fails on one axis has
failed. A model that says "I can't do that" and then does it has not refused.

**A definite block beats an abstention.** Most detectors abstain on most payloads — a
refusal lexicon has no opinion about a tool call — and `INCONCLUSIVE` is how they say
"not my department". Letting an abstention veto a detector that *did* establish a
result would push every well-defended target into the undecidable bucket, which reads
in a report as missing coverage against a target that actually passed.

Genuinely undecidable attempts still reach `INCONCLUSIVE`, because `run_detectors`
returns `INCONCLUSIVE` from every detector when the response is empty or errored.
Silence never reads as safety.

---

## Detector tiers

| Tier | Detectors | Score | Can report a bypass? |
|---|---|---|---|
| Ground truth | `marker.echo`, `canary.leak`, `exfil.url_canary`, `toolcall.forbidden` | 0.9–1.0 | yes |
| Structural | `output.unsafe_markup`, `regex.match` | 0.5–0.9 | yes, hedged |
| Interpretive | `refusal.heuristic`, `injection.disclosure` | ≤0.05 | **no** |

The interpretive tier cannot promote an attempt to a finding — asserted in the test
suite by reading the source. Its only job is to separate "the guardrail held" from
"we could not tell", which is exactly where a lexicon is good enough and a lexicon
alone is not evidence.

`exfil.url_canary` illustrates the distinction the tiers are for: it requires the
sentinel to be **inside a URL**, not merely present. A model that mentions the token
in prose leaked a token; one that put it in an image source built a channel that
fires on render. Those are different severities, so they get different detectors.

---

## Probes and transforms divide the work

**Probes** are hand-built techniques where placement matters — a zero-width split
inside one trigger word, an injection in the `internal_notes` field of a JSON tool
result, a canary planted in an earlier assistant turn.

**Transforms** re-encode *any* payload wholesale, which is how you sweep an encoding
across the whole corpus.

`identity` is always included (the config loader inserts it if you omit it), so every
transformed attempt has an unmutated counterpart. Three readings follow:

- baseline blocked, transform bypassed → the filter matches raw strings and does not
  normalise. An architectural finding, and the transform names the gap.
- both bypassed → the transform is irrelevant; the guardrail was not there.
- baseline bypassed, transform blocked → the transform broke the payload's
  legibility, not the guardrail. Reported, and **not** counted as a defence.

Sentinels are never transformed. Base64-encoding the marker would make every
transformed attempt look blocked — silently, and in the safe-looking direction.

---

## The three orchestrators

| Strategy | Shape | What it buys |
|---|---|---|
| `sweep` | Every payload × transform × target, once | Coverage. Cheap enough for CI. |
| `crescendo` | Walks an escalation ladder, stops at the first bypass | Finds attacks whose objective exists only in the trajectory. The rung it broke on is the finding. |
| `adaptive` | Baseline, then successively stronger transforms until one lands | A *boundary*: plain blocked, base64 not, which locates the defect in the input filter rather than the model. |

All three draw from the same ceilings, so switching strategy changes the shape of the
traffic, never its volume cap. `adaptive` records the extra requests escalation spent
in the run notes, because a plan that understated its own request count would defeat
the point of `redteam plan`.

---

## Metrics: it is all about the denominator

Attack success rate is the number people read first and quote later, and it moves
when you add probes, add transforms, or when a target times out — none of which are
changes in the target's security. So:

- The denominator is **attempts that reached a verdict** (`BYPASSED` + `BLOCKED`).
  Skips, errors, and inconclusives are counted and reported separately.
- `Rate` keeps its counts next to its percentage: `3/4` and `300/400` are the same
  number and very different evidence.
- Resilience is **risk-weighted**, so a target cannot look healthy by blocking a pile
  of low-severity probes while a critical one gets through.
- `coverage_warning` states plainly when a run's numbers should not be trusted.
- Findings are grouped by `(probe, carrier)`: twelve payloads of one probe through
  one carrier is one defect with twelve pieces of evidence, not twelve defects.

---

## Extension points

All six are `Registry` instances. Registration is a decorator, ids are validated at
import time, and selection accepts exact ids, family prefixes, globs, and tags.

```python
from redteam.probes import PROBES, Probe

@PROBES.register("custom.my_technique", summary="One line for `redteam list`")
class MyTechnique(Probe):
    ...
```

See [EXTENDING.md](EXTENDING.md) for the full contract of each point.

---

## `datacheck`: the corpus's supply chain

`redteam.datacheck` validates the research compilation in [`data/`](../data), which is
where the probe corpus comes from — the seven injection families in
`redteam/probes/indirect.py` are a direct encoding of the hypothesis families in
`data/ACTIVE_CHALLENGE_PLAYBOOK.md`. Drift in that document is drift in the
framework's threat model, so it is checked rather than assumed.

It also enforces the data-handling rules that keep this repository publishable, and it
shares its credential/PII pattern table with `redteam.core.redact` — one source of
truth protecting both the committed data and the run artifacts.

Run it with `redteam validate`.
