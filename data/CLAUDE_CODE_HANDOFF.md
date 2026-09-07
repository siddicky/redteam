# Claude Code handoff: Gray Swan Arena research

Snapshot date: **2026-07-29** (re-verified and extended **2026-09-03**)  
Workspace: Gray Swan Arena historical research and active-challenge field kit

## Objective

Continue maintaining and using the Gray Swan Arena research compilation, with special attention to the active **Hazard Hunt Q3** direct-elicitation challenge. The Indirect Prompt Injection July ’26 kit is retained as historical reference; its playbook still anchors the framework's threat model.

## Start here

1. Read `README.md` for the complete historical challenge and public-resource compilation.
2. Read `HAZARD_HUNT_PLAYBOOK.md` for the current active-challenge testing methodology.
3. Use `hazard_hunt_q3_run_log.csv` (copy to a .local.csv twin) to record manual Arena attempts.
4. Treat `ACTIVE_CHALLENGE_PLAYBOOK.md` and `ipi_july_2026_run_log.csv` as historical IPI reference.
5. Use the remaining CSVs for structured challenge, wave, and source data.

## Current findings

- The public Arena catalog exposes 27 named challenges as of the 2026-09-03 sync.
- Of those, 24 were completed and 3 were ongoing/practice.
- Sync delta since the 2026-07-29 snapshot: Indirect Prompt Injection July ’26 has ended (Wave 1 ran Jul 27 – Aug 03 with all $20,000 awarded); Getting Started Quest #1 was rebranded to The Labyrinth (Training Quest #1); two new completed challenges joined the catalog (Indirect Prompt Injection August ’26, $30,000; IPI Lucky Break, a $5,000 Proving Ground raffle).
- The active competitive event is **Hazard Hunt Q3**, a direct-elicitation challenge (re-verified live on 2026-09-03).
- It carries 39 target behaviors across 4 categories:
  - 10 Chemistry behaviors
  - 10 Biology behaviors
  - 9 Misc behaviors
  - 10 Cyber behaviors
- The engagement capture listed 20 anonymized model aliases.
- Scoring is unique by participant, behavior, and model; a break requires every enabled criterion for the behavior to score 7 or higher.
- Energy economics, verified from submission records: 10 per submission, 2 per message, 200 regenerated per hour capped at a 1000 regen balance, and 200 bank energy per credited break.
- Prize pool is $80,000, split into four per-category prizes of $20,000 each; the window runs August 25 through September 11, 2026.
- Historical IPI findings: Wave 1 had 12 behaviors (4 Coding Agent, 3 Computer / Browser Use, 5 Tool Use), 19 aliases in the live UI with 2 temporarily unavailable, and an August 2, 2026 20:59 PT prize snapshot deadline.
- Proving Ground Waves 1–26 are represented in the archive; behaviors for Waves 7, 8, and 10 could not be recovered.
- The source index contains 35 distinct public resources.

## Active event constraints

These are hard requirements from the live challenge rules:

- One account per person.
- Every submission must be entered manually through the Arena.
- No scripts, bots, API submission, macros, or bulk submission tools.
- AI-assisted brainstorming and drafting is allowed.
- No sharing of working breaks, exploits, or submissions until 30 days after the competition.
- Only designated challenge infrastructure is in scope.
- Do not attempt to deanonymize models.
- No denial-of-service or interference with other participants.
- Report Gray Swan infrastructure vulnerabilities responsibly to `arena@grayswan.ai` or the event Discord.

## Important data-handling rule

This export contains public research, methodology, and a blank run-log template. It does **not** contain known working competition solutions, private participant submissions, authentication material, or personal data.

If the run log is later populated:

- Keep working strings and model-specific observations private through the competition embargo.
- Do not commit payloads to a public repository.
- Prefer a local ignored file for full payload text.
- Store only a candidate identifier or local path in the CSV.
- Remove tokens, account details, and personal data before sharing any later export.

## Recommended Claude Code workflow

1. Validate that the live challenge rules and model availability have not changed.
2. Preserve all rule-of-engagement constraints.
3. Select one behavior/model cell.
4. Draft an original candidate from one hypothesis family in the playbook.
5. Ask the human operator to submit it manually.
6. Record the observed result in the run log.
7. Change one mutation dimension at a time.
8. Never automate Arena submissions.
9. Do not publish successful strings during the embargo.

## File map

| File | Purpose |
|---|---|
| `README.md` | Main historical challenge and public walkthrough archive |
| `HAZARD_HUNT_PLAYBOOK.md` | Current Hazard Hunt Q3 field kit |
| `hazard_hunt_q3_run_log.csv` | Hazard Hunt Q3 run-log template (39 behaviors) |
| `ACTIVE_CHALLENGE_PLAYBOOK.md` | Historical IPI July ’26 pentesting checklist |
| `ipi_july_2026_run_log.csv` | Historical IPI manual experiment log template |
| `arena_challenges.csv` | Structured named-challenge catalog |
| `proving_ground_waves.csv` | Structured Proving Ground wave/behavior archive |
| `public_writeups_walkthroughs.csv` | Public resource bibliography |
| `CLAUDE_CODE_HANDOFF.md` | This handoff brief |

## Validation already completed

- `arena_challenges.csv`: 27 data rows.
- `proving_ground_waves.csv`: 95 data rows, including explicit unrecovered-wave markers.
- `public_writeups_walkthroughs.csv`: 35 unique resource URLs.
- `ipi_july_2026_run_log.csv`: 12 behavior rows and 19 columns. (The earlier
  "20 columns" note counted a stray trailing comma on each data row; the
  testing framework flagged the ragged rows and the template was corrected to a
  uniform 19 fields.)
- All CSV files parse successfully with the standard-library CSV parser.

## Known uncertainty

- Waves 7, 8, and 10 were absent from the live Proving Ground UI and available Internet Archive captures.
- One participant post is mapped to The Labyrinth only probabilistically because the article does not explicitly name the challenge.
- Arena status, rules, model availability, and deadlines are time-sensitive and should be reverified before operational use.

