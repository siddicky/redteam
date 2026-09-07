# Authorization

Every target this framework contacts must be covered by an authorization record.
This page is the reference for writing one, what each field does, and how the gate
decides.

The short version: `redteam init` scaffolds a record, you narrow the scope and set
the acknowledgements once the engagement is genuinely signed off, and you pass it
with `--auth`.

---

## The record

```json
{
  "version": 1,
  "engagement": "Q3 2026 internal LLM guardrail assessment — staging assistant",
  "authorized_by": "A. Reviewer, Head of Security Engineering",
  "reference": "SEC-1421",
  "issued": "2026-07-28",
  "expires": "2026-08-28",
  "scope": {
    "targets": [
      "mock:*",
      "http://localhost:*",
      "https://llm.staging.internal.example.com/*",
      "exec:./bin/support-agent"
    ],
    "max_attempts": 500,
    "max_requests_per_minute": 30,
    "max_concurrency": 4,
    "deny": []
  },
  "acknowledgements": {
    "authorized": true,
    "rules_of_engagement_reviewed": true
  },
  "contacts": {
    "escalation": "secops@example.com"
  },
  "notes": "Staging only. Production endpoints are out of scope for this engagement."
}
```

A working copy lives at
[`examples/authorization.example.json`](../examples/authorization.example.json).

### Fields

| Field | Required | Purpose |
|---|---|---|
| `version` | yes | Must be `1`. |
| `engagement` | yes | What this testing is. Appears in every report. |
| `authorized_by` | yes | Who approved it, by name and role. |
| `reference` | no | Ticket or contract id. Ties the run to the paperwork. |
| `issued` | no | ISO date. |
| `expires` | yes | ISO date. An expired record authorizes nothing. |
| `scope.targets` | yes | Endpoint patterns. Non-empty; no catch-all wildcard. |
| `scope.max_attempts` | yes | Attempt ceiling, 1–100000. |
| `scope.max_requests_per_minute` | yes | Rate ceiling. Must be positive. |
| `scope.max_concurrency` | no | Parallel-request ceiling. Omit for unbounded. |
| `scope.deny` | no | Additional denials. Append-only. |
| `acknowledgements` | yes | Both keys must be `true`. |
| `contacts` | no | Escalation details. **Never written to a run artifact.** |
| `notes` | no | Free text for the operator. |

`contacts` is excluded from the run record deliberately: it is personal data, and a
run artifact travels widely.

---

## The three rules

### 1. Default deny

A target is reachable only if its endpoint matches a `scope.targets` pattern. There
is no way to authorize everything — `*`, `**`, `https://*`, and `*://*` are all
rejected at load time:

> authorization scope.targets may not contain the catch-all pattern `'*'`.
> Enumerate the systems you are authorized to test — a blanket wildcard is not an
> authorization.

### 2. Append-only denylist

Operators can refuse additional hosts via `scope.deny`. Built-in entries, if any,
cannot be removed by a local file. Listing a denied host in `scope.targets` does
not unlock it — the denylist is consulted first.

There are currently no built-in denials. `scope.deny` is the only way to add
entries.

Denials raise `PolicyViolation`, which the CLI reports distinctly:

```
REFUSED: target 'https://blocked.example.com/api' is denied: added by scope.deny
in the authorization record
This denial is not configurable. The platform's own rules forbid automated interaction.
```

### 3. Bounded and expiring

Where your config asks for more than the record allows, the record wins and the run
notes record the reduction:

```
- max_attempts lowered from 5000 to 500 by the authorization record
- request rate lowered from 600 to 30 req/min by the authorization record
```

---

## Endpoint patterns

Every target adapter reports an endpoint describing what will actually be
contacted. Patterns are matched against that string.

| Endpoint form | Adapter |
|---|---|
| `https://host/path` | `http.openai_compat`, `http.anthropic`, `http.generic` |
| `exec:<argv[0]>` | `exec.command` |
| `mock:<profile>` | `mock.llm` |
| `replay:<path>` | `replay.transcript` |

Matching rules:

- **Glob on the whole endpoint.** `https://api.internal.example.com/*`, `mock:*`,
  `exec:./bin/agent`.
- **Bare hostname covers the host and its subdomains, on any path.**
  `llm.internal.example.com` matches every URL on that host;
  `internal.example.com` also matches `llm.internal.example.com`.
- **A scheme in the pattern is matched literally.** `http://localhost:8080/*` does
  *not* authorize `https://localhost:8080/...`. Being explicit about the scheme and
  port is the point.

Test before you run — this sends nothing:

```bash
redteam authz --auth authorization.json \
  --target https://llm.staging.internal.example.com/v1/chat/completions \
  --target https://api.openai.com/v1/chat/completions
```

```
endpoint checks:
  ALLOW  https://llm.staging.internal.example.com/v1/chat/completions
  DENY   https://api.openai.com/v1/chat/completions
         target '…' is not in the authorized scope (…). Add it to scope.targets in
         authorization.json only if the engagement actually covers it.
```

Exit code is `0` when every checked endpoint is allowed, `2` otherwise — so this is
usable as a pre-flight step in a pipeline.

---

## Judge endpoints are authorized too

The `judge.llm` detector sends the response under test to a separate model. That is
an outbound call to a third party carrying whatever the target echoed back, so it
goes through the same gate. `prepare_run` collects judge endpoints and authorizes
them **before** the run starts, not on first use halfway through, and records them
in the run notes:

```
- judge endpoint authorized: https://api.anthropic.com/v1/messages
```

If your judge is a hosted API, its host needs to be in `scope.targets`.

---

## Offline targets need no record

`mock:`, `replay:`, and `static:` endpoints reach no network and involve no third
party:

```bash
redteam run --config examples/offline-demo.config.json    # no --auth needed
```

This is why it works, and why it does not weaken the gate: the fallback record
(`Authorization.offline()`) permits *only* those schemes. Point the same config at a
URL and it fails before sending anything:

```
NOT AUTHORIZED: no authorization record supplied, but this config targets live
endpoint(s): https://api.example.com/v1/chat/completions.
Pass --auth authorization.json. Run 'redteam init' to scaffold one, and have the
engagement signed off before you run it.
```

---

## The acknowledgements

```json
"acknowledgements": {
  "authorized": false,
  "rules_of_engagement_reviewed": false
}
```

`redteam init` writes both as `false`, and a record with either unset is rejected:

> authorization acknowledgements must set `authorized=true`,
> `rules_of_engagement_reviewed=true` — this is the operator's attestation that the
> engagement is authorized and the rules of engagement were read

This is the one control the framework cannot verify. A scaffolded file does nothing
until a human changes those two values, which makes it a deliberate act rather than
a default. The test suite asserts the scaffold ships unusable.

---

## Failure modes and what they mean

| Message | Meaning | Exit |
|---|---|---|
| `NOT AUTHORIZED: … not in the authorized scope` | The endpoint is not in `scope.targets`. | 2 |
| `NOT AUTHORIZED: authorization expired on <date>` | Renew the sign-off. | 2 |
| `NOT AUTHORIZED: … needs an authorization record` | Live target, no `--auth`. | 2 |
| `REFUSED: … is denied` | Denylisted host. Not configurable. | 2 |
| `config error: … catch-all pattern` | Scope tries to authorize everything. | 2 |
| `config error: … acknowledgements must set …` | Nobody has attested yet. | 2 |
| `attempt budget exhausted (500/500)` | Ceiling reached; the run stopped sending. | 0/1 |

Exit `2` always means nothing was sent.

---

## Operating notes

**One record per engagement, not per run.** The record describes what you are
allowed to do; configs describe what you are doing today. Keep the record with the
engagement paperwork and reference it from CI.

**Keep expiry short.** A record that expires in a month forces the conversation
again. `redteam authz` prints the days remaining.

**Do not commit it.** `authorization.json` is git-ignored. It names systems, people,
and escalation contacts.

**Narrow the scope as you learn.** Starting broad and narrowing later is backwards —
the broad version is what runs on the day you make a mistake.

**Put the escalation contact in.** It ends up in front of whoever is running the tool
at the moment something unexpected comes back, which is exactly when it is needed.
