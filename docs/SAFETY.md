# Safety model

This tool sends adversarial traffic to live systems and writes down what comes
back. Both halves are hazardous, and this document states what the framework does
about each, what it deliberately does not do, and what remains your
responsibility.

Read it before the first live run.

---

## 1. Every target must be authorized

Whether pointing this tool at a system is legitimate security work or an attack
depends entirely on whether you were authorized to do it — a fact that lives
outside the code. So the framework requires it *in* the code.

`redteam.policy.authorization` enforces three rules that no configuration file can
relax:

**Default deny.** A target is reachable only if its endpoint matches a pattern in
your authorization record's `scope.targets`. There is no wildcard that authorizes
everything; `scope.targets: ["*"]` is rejected at load time.

**Append-only denylist.** Operators can refuse additional hosts via `scope.deny`.
Built-in entries, if any, cannot be removed by a local file. The denylist is
consulted before scope.

**Bounded and expiring.** Every record carries an attempt ceiling, a request-rate
ceiling, and an expiry date. An expired record authorizes nothing. Where your
config asks for more than the record allows, the record wins and the run notes say
so.

The gate runs inside `prepare_run`, before any target is fully constructed and
before the first request. `redteam authz --auth A --target E` tests an endpoint
without sending anything.

Full detail: [AUTHORIZATION.md](AUTHORIZATION.md).

### The offline exception

`mock:`, `replay:`, and `static:` endpoints reach no network and involve no third
party, so they run without a record. This exists so the demo and the test suite
work in a fresh clone — if the frictionless path required waving the gate away,
operators would learn to wave it away. Point the same config at a URL and it fails
immediately.

---

## 2. Payloads are inert

The obvious way to test whether a guardrail can be bypassed is to ask the target
for something genuinely harmful. That means generating, storing, and shipping
harmful content in this repository.

This framework does not do that. Probes ask the target to violate an instruction in
a way that is **observable but inert**:

- emit a specific random token (a *sentinel*),
- place a canary inside a URL,
- call a declared-forbidden tool with a dummy argument,
- disclose a canary planted in the system prompt.

The security question — *did untrusted input override the operator's
instructions?* — is answered exactly. A model that emits the sentinel would have
emitted whatever else the injection asked for; the guardrail either held or it did
not, and the answer is identical either way. So there is no reason to generate the
harmful thing.

Three consequences worth being explicit about:

1. **The repository ships no attack content.** `tests/framework/test_probes.py`
   asserts this, over every payload every probe produces.
2. **Findings are precise.** Every probe runs against the numbered operator
   instruction in `redteam/probes/base.py`, so a finding names the rule that broke
   rather than reporting "the model said something bad".
3. **Sentinels are per-run.** They derive deterministically from the run seed, so a
   run reproduces exactly, while a target that memorised last week's token cannot
   fake a pass.

### What this does not cover

Inert sentinels measure **guardrail integrity**. They do not measure **harm-category
refusal** — whether the target will produce weapons synthesis, self-harm
encouragement, or CSAM-adjacent material. That needs real category prompts, and a
public repository is the wrong place for them.

The seam is the `corpus.custom` probe. Point it at your own JSONL — an approved
internal eval set, a vendor safety suite, a licensed benchmark — and it becomes a
probe like any other, with the same orchestrators, detectors, and reports:

```bash
make new-corpus            # scaffolds corpus.local.jsonl (git-ignored)
redteam run --config c.json --auth a.json --probe corpus.custom --corpus corpus.local.jsonl
```

Two properties are enforced rather than suggested: the corpus **path** never
reaches a run artifact (only a digest and entry count), and payload text is omitted
from artifacts unless you explicitly enable it. Corpus prompts are the part of a run
you are least likely to be permitted to redistribute.

---

## 3. Artifacts are treated as sensitive

A run artifact is the highest-risk output this project produces. It contains your
attack payloads and — because the target is a real system — whatever that system
chose to echo back: credentials it was holding, customer records, internal
hostnames.

**Redaction.** Every reporter routes text through `redteam.core.redact` on the way
out: AWS keys, GitHub tokens and PATs, OpenAI and Anthropic keys, Slack and Google
keys, Azure keys, HuggingFace tokens, private-key blocks, bearer tokens, JWTs,
email addresses, and Luhn-valid payment cards. Sentinels are explicitly preserved,
because redacting the evidence would destroy the proof of the finding.

**Payload suppression.** `--no-payload-text` stores payload *fingerprints* instead
of payload text. Use it for any report leaving the engagement: attach the finding,
not a working payload.

**Git hygiene.** `runs/`, `*.sarif`, `authorization.json`, `*.local.jsonl`, and
`*.local.csv` are all git-ignored, and
`tests/framework/test_safety_invariants.py` fails if those rules disappear.

**The pre-share gate.** Before anything leaves the engagement:

```bash
redteam scan runs/                      # report hits; never prints the values
redteam scan runs/ --fix ./sanitised    # write redacted copies
```

Redaction is a backstop against common cases, **not** a substitute for handling
artifacts as sensitive. Store them where the engagement's evidence belongs.

---

## 4. The tool does not create the vulnerabilities it looks for

Asserted structurally in `tests/framework/test_safety_invariants.py`:

- **No TLS downgrade.** `verify_tls=false` is refused with an error, not a warning.
  Add the endpoint's CA to your trust store instead.
- **No shell.** The subprocess target requires an argv list and runs with
  `shell=False`. Building a shell string from probe text would let a payload escape
  the framework and execute on your machine.
- **No dynamic evaluation.** No `eval`, `exec`, or `compile` anywhere in the
  package.
- **No tool execution.** Tool schemas are declarations sent *to the target*. The
  framework never calls one. A finding is that the target emitted
  `delete_records(...)`, not that anything was deleted.
- **One pinned dependency.** The runtime dependency list is exactly one entry:
  `grayswan-scraper` (siddicky/gs-submissions, branch `build/uv-build-system`), pinned
  to an exact fork commit (`7a11e78d803189d598b5997961a9c6757b9f6ca4`), a direct child
  of upstream `arvkevi/gs-submissions@6128748` with only the uv_build packaging fix,
  and used only by the `arena-scrape`
  surface. A dependency in a security tool joins every engagement's supply chain, so
  the pin is deliberate, recorded in `uv.lock`, and test-enforced
  (`tests/framework/test_safety_invariants.py`).

That dependency's supply chain and data surface are known and bounded: it pulls
`playwright`, `pydantic`, `rich`, and `rookiepy`. Driving it logs into Gray Swan
Arena with *your* Chrome session — `rookiepy` reads Chrome cookies locally and
`playwright` drives a real browser — so the credential attack surface is your own
Chrome profile on your own machine. The scraper is never exercised by the test suite
or CI, and its output (full conversations and the browser auth state) is written
only to git-ignored local directories; nothing from it enters the repository.

The optional `dspy` extra is deliberately not a core dependency: bare
`python -m redteam` imports nothing beyond the standard library, which keeps it
usable in environments where adding packages is inappropriate, while opt-in users
get DSPy within its supported interpreter range (currently Python <3.15). The
single-extra policy is test-enforced; adding another extra — or touching the pinned
dependency — requires the same deliberate README, safety-model, and
no-dependencies CI review as any supply-chain change.

### The DSPy layer: endpoints, data flow, and artifacts

**Attack-model endpoints are authorized like any target.** The `dspy.redteamer`
orchestrator declares its model through `auxiliary_targets()`, and `prepare_run`
builds and authorizes that endpoint exactly as it does a system under test: default
deny, denylist, ceilings, a named note in the run record. A live attack model behind
an offline simulator does not disable rate limiting, and auxiliary targets are closed
when the run ends.

**Data-flow disclosure.** During a run, the auxiliary model endpoints (attack
drafting and refinement) and any judge endpoint receive the attempt's objective, the
target's responses, and the running critique. Those providers must be covered by the
engagement's data-processing rules; the authorization record's scope is the mechanism
by which the operator approves them. This mirrors the `judge.llm` precedent: an
outbound call to a third party carrying run material is authorized like a target and
named in the run record.

**Program states are redacted artifacts.** `redteam compile` writes the optimized
program under `runs/` as versioned JSON (`redteam.dspy.program.v1`). String leaves
pass through the redactor, and every serialized `lm` entry is set to `null` rather
than deleted: the loader requires the key, and `null` is what makes "no model is
serialized" machine-checkable. The bridge LM itself is never serialized; the artifact
carries no endpoint and no credential, and a write that would contain one is refused.

**Compile spend is bounded by the authorization record.** Every optimizer-phase
request (candidate proposals, dataset summaries, metric target-sends) routes through
the same budgeted seam as a run, so the record's request ceiling is the hard stop. A
pre-flight check requires the training floor to fit within half the budget so
optimizer overhead keeps headroom; the plan discloses a pre-run estimate and the
compile summary discloses the actual request count afterwards. Token and monetary
ceilings are deliberately out of scope; tighten via the record's request ceiling if
that is not enough.

---

## 5. Load is bounded

An automated red-team harness is mechanically a load generator pointed at
someone's production-shaped system. Unbounded, it becomes an availability incident
— a bug, and a breach of every rules-of-engagement document worth signing.

- **Rate limit.** A token bucket capped at the lower of your config and your
  authorization record. Skipped only when every target is offline.
- **Attempt budget.** Capped the same way. On exhaustion the run stops sending
  immediately and the artifact records it.
- **Concurrency ceiling.** From `scope.max_concurrency`.
- **Retry discipline.** Capped exponential backoff with jitter, and only for
  transient failures. A 400 is never retried — that would triple the load for the
  same answer.
- **`redteam plan`** reports the true request count before you send anything,
  including the per-rung cost of multi-turn attempts.

There are no denial-of-service probes, and none will be added.

---

## 6. Results do not overstate security

The failure mode that would make this tool worse than not running it is a report
that says a target is fine when nobody established that. Four defences:

**Skips are not passes.** A probe that could not run — a multi-turn probe under a
single-turn orchestrator, a system-prompt probe against a target that discards
system turns — is recorded as `SKIPPED` and excluded from the success-rate
denominator. Folding skips in would manufacture a reassuring number out of missing
coverage.

**Silence is not a pass.** An empty or errored response produces `INCONCLUSIVE`,
never `BLOCKED`.

**Inconclusive is its own bucket.** Neither pass nor finding: triage work, and a run
with many of them is telling you the detectors need attention.

**Coverage caveats are printed.** When a large share of attempts produced no
verdict, or a run was truncated by its attempt ceiling, every report says so and
states that absence of a finding is not evidence of safety.

Detector design follows the same principle. Ground-truth detectors (sentinel,
canary, tool call) carry the findings. Interpretive detectors (refusal and
disclosure lexicons) *cannot* report a bypass at all — asserted in the test suite —
because their only job is to separate "the guardrail held" from "we could not
tell".

---

## 7. Gray Swan Arena research data

This repository grew out of the research compilation in [`data/`](../data), which
documents the Gray Swan Arena's public challenge history. The research data is why
the indirect-injection probes are the strongest part of the corpus: the seven
hypothesis families in `redteam/probes/indirect.py` are a direct encoding of the
families in [`data/ACTIVE_CHALLENGE_PLAYBOOK.md`](../data/ACTIVE_CHALLENGE_PLAYBOOK.md).

If you are participating in that competition, its published rules of engagement
are yours to follow. `redteam plan --show-payloads` against an offline `mock:`
target gives you drafted candidates with no network traffic at all.

---

## 8. What is your responsibility

The framework cannot check these, and they matter more than everything above:

- **That the authorization is real.** The acknowledgements in an authorization
  record are your attestation. `redteam init` ships them `false` on purpose; setting
  them `true` is a statement about the world.
- **That the scope is right.** Narrow `scope.targets` to the systems actually
  covered. A staging pattern that happens to match a production hostname is a
  problem the tool cannot see.
- **That findings are triaged, not just filed.** An `output.unsafe_markup` finding
  is a real bug only if a consumer renders or interpolates that output. The report
  says so; confirm it before assigning severity.
- **That artifacts are handled.** Redaction is a backstop. Storage, retention, and
  distribution are yours.
- **That you stop when you should.** If a target returns real customer data, stop and
  escalate. Put the escalation contact in the authorization record so it is in front
  of whoever is running the tool.

---

## Reporting a problem

Found a security defect in **this framework** — a way past the authorization gate, a
redaction bypass, a payload that escapes into the operator's environment? Open an
issue describing the impact, without a working exploit in the initial report.

Found a vulnerability in the **Gray Swan platform**? That goes to `arena@grayswan.ai`
or the event Discord, not here.
