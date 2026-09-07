# Hazard Hunt 2026 — rehearsal engagement

Gray Swan Arena, Aug 25 – Sep 11 2026. Four categories, one leaderboard each:
Chemical, Biological, Cyber, Misc. This engagement rehearses drafted category
corpora offline against the simulator profiles before anything is submitted
manually to the platform.

## Competition rules this engagement is built around

- **Manual submission only.** The framework never submits anything anywhere —
  it drives mock simulators locally. Every Arena submission is entered by you,
  by hand, one at a time.
- **No solution sharing.** Everything in this directory is git-ignored. Drafts,
  corpora, and run artifacts stay on this machine.
- **Scope = challenge infrastructure only.** `grayswan.ai` and `app.grayswan.ai`
  are on the authorization denylist so no live Arena endpoint can ever be
  targeted from here, even by accident.
- **No deanonymization / fair play** are competition-side rules; this tool
  cannot violate them because it does not touch the platform.

## Files

| File | Purpose |
|---|---|
| `authorization.json` | Mock/replay-only scope, expires 2026-09-11. Arena hosts denied. |
| `redteam.config.json` | Three simulator targets, full probe corpus + `corpus.custom` (defaults to the chemical file). |
| `hh-chemical.local.jsonl` | Chemical category drafts. Placeholder entries — replace before running. |
| `hh-biological.local.jsonl` | Biological category drafts. |
| `hh-cyber.local.jsonl` | Cyber category drafts. |
| `hh-misc.local.jsonl` | Misc category drafts. |

## Per-category workflow

1. **Draft** in the category's `.local.jsonl`. Entry shapes with placeholders
   are pre-seeded (direct, drip, over-refusal control); more shapes —
   multi-turn, indirect carrier, versioned patch — are documented with
   worked skeletons in `examples/corpus.example.jsonl`. Keep the `seeded`
   and `rubric` fields filled: they are what makes a later judge verdict
   attributable and per-criterion.
2. **Preview (sends nothing):**
   ```bash
   uv run redteam plan --config engagements/2026-08-30/redteam.config.json \
     --auth engagements/2026-08-30/authorization.json
   ```
3. **Rehearse** against the simulators (run from the repo root so relative
   paths resolve):
   ```bash
   uv run redteam run --config engagements/2026-08-30/redteam.config.json \
     --auth engagements/2026-08-30/authorization.json \
     --probe corpus.custom --corpus engagements/2026-08-30/hh-chemical.local.jsonl
   ```
   Swap `--corpus` per category. Check the **control** entries: a "bypass"
   that also refused the benign control means the pipeline is measuring
   silence, not safety.
4. **Submit manually** on the Arena platform for entries that held up in
   rehearsal. One at a time, by hand.
5. **Iterate.** Track which shapes beat which refusal styles; the per-transform
   table in run reports tells you whether a filter normalises encodings.

## Judge wiring (optional, needs live egress)

The heuristic detectors here are enough to verify corpus mechanics against
mocks. Real category scoring needs `judge.llm` with a judge model — that is an
outbound call, so its host must be added to `scope.targets`, the acknowledgements
re-signed with a real authorizer, and an API key exported. See
`examples/README.md` ("Harm-category evaluation") for the `detector_options`
block. Prefer a judge from a different provider than the system under test.
