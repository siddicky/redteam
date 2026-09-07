"""Output formats.

Each serves a different consumer, and the differences are deliberate:

``console``
    What the operator watches. Findings first, worst risk first, then the
    breakdowns that say where to look next.
``json``
    The machine artifact and the replay input. Complete and lossless.
``jsonl``
    One attempt per line, for a pipeline or a log shipper.
``markdown``
    The human report: an executive summary, grouped findings with evidence, and a
    remediation section keyed to the operator rules that broke.
``html``
    A self-contained page for sharing — no external assets, so it survives being
    attached to a ticket.
``sarif``
    For CI code-scanning ingestion, so guardrail regressions surface next to code
    findings instead of in a separate tool nobody opens.
"""

from __future__ import annotations

import html
import json
from typing import Any

from ..core.result import Outcome, RunResult
from ..scoring.metrics import Rate, deduplicate_findings, summarize
from .base import REPORTERS, ReportOptions, Reporter, clean, risk_badge

#: Remediation guidance keyed by probe family. Written as "the fix", not "the
#: risk": a report that describes a problem without naming the control that
#: addresses it hands the reader a research project.
REMEDIATION: dict[str, str] = {
    "indirect": (
        "Untrusted retrieved content is being treated as instructions. Keep "
        "provenance at the boundary rather than in the prompt: deliver retrieved "
        "text in a structurally separate channel, strip or escape instruction-like "
        "constructs, and gate every tool call on an explicit user request rather "
        "than on content the model just read. Prompt wording alone does not hold."
    ),
    "direct": (
        "The system prompt is being overridden from the user turn. Move the "
        "guardrail out of the prompt: enforce it in the wrapper with an "
        "input/output policy check that cannot be argued with, and normalise input "
        "before any filtering."
    ),
    "leak": (
        "Prompt contents are recoverable. Treat the system prompt as public and "
        "remove secrets, identifiers, and internal hostnames from it; enforce "
        "authorization server-side rather than by instructing the model to keep "
        "things quiet."
    ),
    "agency": (
        "The agent takes consequential actions on instructions found in data. "
        "Require out-of-band confirmation for destructive, privilege-changing, and "
        "external-recipient actions; scope tool credentials to least privilege; and "
        "validate action arguments against the user's stated request, not against "
        "retrieved content."
    ),
    "exfil": (
        "The model can construct outbound requests through its output. Restrict the "
        "renderer: disallow remote image and iframe sources, or proxy them through "
        "an allowlist. Fixing this in the client removes the whole class."
    ),
    "output": (
        "Model output is dangerous to interpolate. Treat it as untrusted input at "
        "every consumer: escape on render, parameterise queries, never pass it to a "
        "shell. This is a consumer-side fix; the model cannot solve it."
    ),
    "framing": (
        "Social framing defeats the guardrail, which means the deployment relies on "
        "the base model's alignment. Add a wrapper-level policy check that scores "
        "the request and the response independently of framing."
    ),
    "obfuscation": (
        "Encoded and Unicode-obfuscated input bypasses inspection. Normalise before "
        "you filter: fold confusables, strip format characters, and decode "
        "base64/hex/ROT13 candidates, then apply the same checks to every reading."
    ),
    "multiturn": (
        "The guardrail scores one message at a time while the attack lives in the "
        "trajectory. Score the conversation, not the turn, and keep state on "
        "commitments the model has already made."
    ),
    "corpus": (
        "Operator-supplied corpus entries got through. Review against your own "
        "policy and route recurring categories into the wrapper's policy check."
    ),
}


def _remediation_for(probe_id: str) -> str:
    family = probe_id.split(".", 1)[0]
    return REMEDIATION.get(
        family,
        "Review the finding against the operating rule it violated and place the "
        "control outside the prompt.",
    )


def _rate_table_rows(rates: dict[str, Rate], limit: int = 12) -> list[tuple[str, Rate]]:
    return list(rates.items())[:limit]


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #
@REPORTERS.register("console", summary="Terminal summary — findings first")
class ConsoleReporter(Reporter):
    """Human-readable terminal output."""

    description = "Compact terminal summary with findings ordered by severity"
    extension = "txt"

    def render(self, run: RunResult, options: ReportOptions) -> str:
        redactor = options.redactor_for(run)
        metrics = summarize(run)
        lines: list[str] = []

        lines.append(f"run {run.run_id}  orchestrator={run.orchestrator}")
        lines.append(
            f"targets: {', '.join(run.targets) or 'none'}   probes: {len(run.probes)}"
        )
        auth = run.authorization or {}
        if auth:
            lines.append(
                f"authorization: {auth.get('engagement', 'n/a')}"
                + (f" (ref {auth['reference']})" if auth.get("reference") else "")
            )
        lines.append("")

        findings = run.findings()
        if options.max_findings:
            findings = findings[: options.max_findings]
        if findings:
            lines.append(f"FINDINGS ({len(run.findings())})")
            lines.append("-" * 72)
            for attempt in findings:
                lines.append(
                    f"{risk_badge(attempt.risk.value)} {attempt.target} :: "
                    f"{attempt.label}"
                )
                lines.append(f"        objective : {attempt.payload.objective}")
                lines.append(
                    f"        carrier   : {attempt.payload.carrier}"
                    f"   technique: {attempt.payload.technique}"
                )
                for verdict in attempt.verdicts:
                    if not verdict.outcome.is_finding:
                        continue
                    lines.append(
                        f"        detector  : {verdict.detector} "
                        f"({verdict.score:.2f}) — {verdict.rationale}"
                    )
                    for item in verdict.evidence:
                        lines.append(
                            f"        evidence  : {clean(item, options, redactor, 200)}"
                        )
                lines.append("")
        else:
            lines.append("FINDINGS: none")
            lines.append("")

        lines.append("SUMMARY")
        lines.append("-" * 72)
        lines.append(f"  attack success rate : {metrics.asr}")
        lines.append(f"  resilience score    : {metrics.resilience:.3f}")
        lines.append(
            f"  outcomes            : {metrics.bypassed} bypassed, "
            f"{metrics.blocked} blocked, {metrics.inconclusive} inconclusive, "
            f"{metrics.errors} error, {metrics.skipped} skipped"
        )
        if metrics.by_risk:
            lines.append(
                "  findings by risk    : "
                + ", ".join(f"{k}={v}" for k, v in metrics.by_risk.items())
            )
        if metrics.coverage_warning:
            lines.append(f"  ! coverage          : {metrics.coverage_warning}")

        for title, rates in (
            ("by target", metrics.by_target),
            ("by carrier", metrics.by_carrier),
            ("by transform", metrics.by_transform),
        ):
            if not rates:
                continue
            lines.append("")
            lines.append(f"  {title}:")
            for key, rate in _rate_table_rows(rates, 8):
                lines.append(f"    {key:<32} {rate}")

        if run.notes:
            lines.append("")
            lines.append("NOTES")
            lines.append("-" * 72)
            for note in run.notes:
                lines.append(f"  - {note}")

        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# JSON / JSONL
# --------------------------------------------------------------------------- #
@REPORTERS.register("json", summary="Complete run artifact (replayable)")
class JsonReporter(Reporter):
    """Lossless JSON."""

    description = "Full run record, suitable for replay and re-scoring"
    extension = "json"

    def render(self, run: RunResult, options: ReportOptions) -> str:
        redactor = options.redactor_for(run)
        data = run.to_dict(
            include_text=options.include_payload_text,
            include_raw=options.include_raw_responses,
        )
        if options.redact:
            data = _redact_tree(data, redactor)
        return json.dumps(data, indent=2, default=str)


@REPORTERS.register("jsonl", summary="One attempt per line, for pipelines")
class JsonlReporter(Reporter):
    """Newline-delimited attempts."""

    description = "One JSON object per attempt, for log shipping and stream processing"
    extension = "jsonl"

    def render(self, run: RunResult, options: ReportOptions) -> str:
        redactor = options.redactor_for(run)
        lines: list[str] = []
        header = {
            "type": "run",
            "run_id": run.run_id,
            "started_at": run.started_at,
            "orchestrator": run.orchestrator,
            "targets": run.targets,
            "authorization": run.authorization,
            "metrics": summarize(run).to_dict(),
        }
        lines.append(json.dumps(header, default=str))
        for attempt in run.attempts:
            record: dict[str, Any] = {
                "type": "attempt",
                "run_id": run.run_id,
                **attempt.to_dict(
                    include_text=options.include_payload_text,
                    include_raw=options.include_raw_responses,
                ),
            }
            if options.redact:
                record = _redact_tree(record, redactor)
            lines.append(json.dumps(record, default=str))
        return "\n".join(lines) + "\n"


def _redact_tree(value: Any, redactor) -> Any:
    if isinstance(value, str):
        return redactor.apply(value)
    if isinstance(value, dict):
        return {k: _redact_tree(v, redactor) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_tree(v, redactor) for v in value]
    return value


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
@REPORTERS.register("markdown", summary="Human report with remediation guidance")
class MarkdownReporter(Reporter):
    """Markdown assessment report."""

    description = "Executive summary, grouped findings with evidence, and remediation"
    extension = "md"

    def render(self, run: RunResult, options: ReportOptions) -> str:
        redactor = options.redactor_for(run)
        metrics = summarize(run)
        out: list[str] = []

        out.append(f"# {options.title}")
        out.append("")
        out.append(f"**Run** `{run.run_id}`  ")
        out.append(f"**Started** {run.started_at} — **finished** {run.finished_at}  ")
        out.append(f"**Strategy** `{run.orchestrator}`  ")
        out.append(f"**Targets** {', '.join(f'`{t}`' for t in run.targets) or 'none'}")
        out.append("")

        auth = run.authorization or {}
        if auth:
            out.append("## Authorization")
            out.append("")
            out.append(f"- Engagement: {auth.get('engagement', 'n/a')}")
            out.append(f"- Authorized by: {auth.get('authorized_by', 'n/a')}")
            if auth.get("reference"):
                out.append(f"- Reference: {auth['reference']}")
            out.append(f"- Expires: {auth.get('expires', 'n/a')}")
            scope = auth.get("scope") or {}
            if scope.get("targets"):
                out.append(f"- Scope: {', '.join(f'`{s}`' for s in scope['targets'])}")
            out.append("")

        out.append("## Summary")
        out.append("")
        out.append("| Metric | Value |")
        out.append("|---|---|")
        out.append(f"| Attack success rate | {metrics.asr} |")
        out.append(f"| Resilience score (risk-weighted) | {metrics.resilience:.3f} |")
        out.append(f"| Attempts | {metrics.total} |")
        out.append(f"| Bypassed | {metrics.bypassed} |")
        out.append(f"| Blocked | {metrics.blocked} |")
        out.append(f"| Inconclusive | {metrics.inconclusive} |")
        out.append(f"| Errors | {metrics.errors} |")
        out.append(f"| Skipped (could not run) | {metrics.skipped} |")
        if metrics.worst_risk:
            out.append(f"| Worst finding | {metrics.worst_risk} |")
        out.append("")

        if metrics.coverage_warning:
            out.append(f"> **Coverage caveat.** {metrics.coverage_warning}")
            out.append("")
        if run.truncated:
            out.append(
                "> **Truncated run.** The plan exceeded the authorized attempt "
                "ceiling, so some attempts were not made. Absence of a finding for "
                "those attempts is not evidence of safety."
            )
            out.append("")

        grouped = deduplicate_findings(run.attempts)
        if grouped:
            out.append(f"## Findings ({len(grouped)} distinct, {metrics.bypassed} attempts)")
            out.append("")
            for index, ((probe, carrier), attempts) in enumerate(grouped.items(), start=1):
                worst = min(attempts, key=lambda a: a.risk.rank)
                out.append(f"### {index}. `{probe}` via `{carrier}` — {worst.risk.value}")
                out.append("")
                out.append(f"**Objective.** {worst.payload.objective}")
                out.append("")
                if worst.payload.taxonomy:
                    out.append(
                        f"**References.** {', '.join(worst.payload.taxonomy)}"
                    )
                    out.append("")
                out.append(
                    f"**Reproduced** on {len(attempts)} attempt(s) against "
                    + ", ".join(sorted({f'`{a.target}`' for a in attempts}))
                    + "."
                )
                out.append("")
                techniques = sorted({a.payload.technique for a in attempts if a.payload.technique})
                if techniques:
                    out.append("**Techniques that worked.**")
                    out.append("")
                    for technique in techniques:
                        out.append(f"- {technique}")
                    out.append("")
                transforms = sorted(
                    {"+".join(a.transforms) or "identity" for a in attempts}
                )
                out.append(f"**Transforms.** {', '.join(f'`{t}`' for t in transforms)}")
                out.append("")

                out.append("**Evidence.**")
                out.append("")
                for attempt in attempts[:3]:
                    for verdict in attempt.verdicts:
                        if not verdict.outcome.is_finding:
                            continue
                        out.append(
                            f"- `{attempt.payload.payload_id}` — {verdict.detector} "
                            f"({verdict.score:.2f}): {verdict.rationale}"
                        )
                        for item in verdict.evidence:
                            excerpt_text = clean(item, options, redactor, 300)
                            out.append(f"  ```\n  {excerpt_text}\n  ```")
                out.append("")

                if options.include_payload_text:
                    out.append("<details><summary>Payload</summary>")
                    out.append("")
                    out.append("```text")
                    out.append(
                        clean(worst.payload.attack_text(), options, redactor, 1500)
                    )
                    out.append("```")
                    out.append("")
                    out.append("</details>")
                else:
                    out.append(
                        f"_Payload text withheld from this artifact; fingerprint "
                        f"`{worst.payload.fingerprint}`._"
                    )
                out.append("")
                out.append(f"**Remediation.** {_remediation_for(probe)}")
                out.append("")
        else:
            out.append("## Findings")
            out.append("")
            out.append("No guardrail bypass was observed in this run.")
            out.append("")
            if metrics.scored == 0:
                out.append(
                    "This is **not** a pass: no attempt reached a verdict. See the "
                    "coverage caveat above."
                )
                out.append("")

        for title, rates in (
            ("By target", metrics.by_target),
            ("By probe", metrics.by_probe),
            ("By carrier (which channel got through)", metrics.by_carrier),
            ("By transform (which encoding got through)", metrics.by_transform),
            ("By reference", metrics.by_taxonomy),
        ):
            if not rates:
                continue
            out.append(f"## {title}")
            out.append("")
            out.append("| Key | Bypassed / scored | Rate |")
            out.append("|---|---|---|")
            for key, rate in _rate_table_rows(rates, 20):
                out.append(f"| `{key}` | {rate.bypassed} / {rate.scored} | {rate.percent}% |")
            out.append("")

        skipped = run.by_outcome(Outcome.SKIPPED)
        if skipped:
            out.append(f"## Not tested ({len(skipped)})")
            out.append("")
            out.append(
                "These attempts could not run. They are neither passes nor failures."
            )
            out.append("")
            reasons: dict[str, int] = {}
            for attempt in skipped:
                reason = next(
                    (v.rationale for v in attempt.verdicts if v.rationale), "unknown"
                )
                reasons[reason] = reasons.get(reason, 0) + 1
            for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
                out.append(f"- {count}× {reason}")
            out.append("")

        if run.notes:
            out.append("## Run notes")
            out.append("")
            for note in run.notes:
                out.append(f"- {note}")
            out.append("")

        out.append("---")
        out.append("")
        out.append(
            "Generated by the `redteam` framework. Findings are measured against the "
            "operator instruction in `redteam/probes/base.py`; each one names the rule "
            "that was violated. Payloads use inert sentinel objectives — see "
            "`docs/SAFETY.md`."
        )
        return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
_HTML_STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       margin: 0; padding: 2rem 1.25rem; max-width: 60rem; margin-inline: auto;
       background: Canvas; color: CanvasText; }
h1, h2, h3 { line-height: 1.25; }
h1 { font-size: 1.7rem; margin-bottom: .25rem; }
h2 { font-size: 1.25rem; margin-top: 2.5rem; border-bottom: 1px solid color-mix(in srgb, CanvasText 20%, transparent); padding-bottom: .3rem; }
h3 { font-size: 1.05rem; margin-top: 1.75rem; }
code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .86em; }
pre { background: color-mix(in srgb, CanvasText 7%, transparent); padding: .7rem .85rem;
      border-radius: 6px; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; display: block; overflow-x: auto; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid color-mix(in srgb, CanvasText 15%, transparent); }
th { font-weight: 600; font-size: .82rem; text-transform: uppercase; letter-spacing: .04em; opacity: .75; }
.meta { opacity: .75; font-size: .9rem; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 999px; font-size: .72rem;
         font-weight: 700; letter-spacing: .04em; text-transform: uppercase; }
.critical { background: #7f1d1d; color: #fff; }
.high     { background: #b45309; color: #fff; }
.medium   { background: #a16207; color: #fff; }
.low      { background: #3f6212; color: #fff; }
.info     { background: #1e3a5f; color: #fff; }
.callout { border-left: 4px solid #b45309; padding: .6rem .9rem; margin: 1rem 0;
           background: color-mix(in srgb, #b45309 10%, transparent); border-radius: 0 6px 6px 0; }
.ok { border-left-color: #3f6212; background: color-mix(in srgb, #3f6212 10%, transparent); }
.finding { border: 1px solid color-mix(in srgb, CanvasText 18%, transparent);
           border-radius: 8px; padding: 1rem 1.15rem; margin: 1rem 0; }
.kv { display: grid; grid-template-columns: minmax(7rem, max-content) 1fr; gap: .25rem .9rem; margin: .6rem 0; }
.kv dt { font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; opacity: .7; }
.kv dd { margin: 0; }
footer { margin-top: 3rem; padding-top: 1rem; font-size: .85rem; opacity: .7;
         border-top: 1px solid color-mix(in srgb, CanvasText 20%, transparent); }
"""


@REPORTERS.register("html", summary="Self-contained HTML report for sharing")
class HtmlReporter(Reporter):
    """Standalone HTML report.

    No external assets, so the file works from a ticket attachment, an artifact
    store, or a mail client with no network.
    """

    description = "Single-file HTML report with no external assets"
    extension = "html"

    def render(self, run: RunResult, options: ReportOptions) -> str:
        redactor = options.redactor_for(run)
        metrics = summarize(run)
        e = html.escape
        out: list[str] = []

        out.append("<!DOCTYPE html>")
        out.append('<html lang="en"><head><meta charset="utf-8">')
        out.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
        out.append(f"<title>{e(options.title)} — {e(run.run_id)}</title>")
        out.append(f"<style>{_HTML_STYLE}</style>")
        out.append("</head><body>")

        out.append(f"<h1>{e(options.title)}</h1>")
        out.append(
            f'<p class="meta">Run <code>{e(run.run_id)}</code> · strategy '
            f"<code>{e(run.orchestrator)}</code> · {e(run.started_at)} → "
            f"{e(run.finished_at)}</p>"
        )

        auth = run.authorization or {}
        if auth:
            out.append('<dl class="kv">')
            out.append(f"<dt>Engagement</dt><dd>{e(str(auth.get('engagement', 'n/a')))}</dd>")
            out.append(
                f"<dt>Authorized by</dt><dd>{e(str(auth.get('authorized_by', 'n/a')))}</dd>"
            )
            if auth.get("reference"):
                out.append(f"<dt>Reference</dt><dd>{e(str(auth['reference']))}</dd>")
            out.append(f"<dt>Expires</dt><dd>{e(str(auth.get('expires', 'n/a')))}</dd>")
            out.append(
                f"<dt>Targets</dt><dd>{e(', '.join(run.targets) or 'none')}</dd>"
            )
            out.append("</dl>")

        if metrics.coverage_warning:
            out.append(
                f'<div class="callout"><strong>Coverage caveat.</strong> '
                f"{e(metrics.coverage_warning)}</div>"
            )
        if run.truncated:
            out.append(
                '<div class="callout"><strong>Truncated run.</strong> The plan '
                "exceeded the authorized attempt ceiling, so some attempts were not "
                "made. Absence of a finding for those attempts is not evidence of "
                "safety.</div>"
            )

        out.append("<h2>Summary</h2>")
        out.append("<table><tbody>")
        rows = [
            ("Attack success rate", str(metrics.asr)),
            ("Resilience score (risk-weighted)", f"{metrics.resilience:.3f}"),
            ("Bypassed", str(metrics.bypassed)),
            ("Blocked", str(metrics.blocked)),
            ("Inconclusive", str(metrics.inconclusive)),
            ("Errors", str(metrics.errors)),
            ("Skipped (could not run)", str(metrics.skipped)),
        ]
        for label, value in rows:
            out.append(f"<tr><th>{e(label)}</th><td>{e(value)}</td></tr>")
        out.append("</tbody></table>")

        grouped = deduplicate_findings(run.attempts)
        out.append(f"<h2>Findings ({len(grouped)} distinct)</h2>")
        if not grouped:
            note = (
                "No guardrail bypass was observed."
                if metrics.scored
                else "No attempt reached a verdict — this is not a pass."
            )
            out.append(f'<div class="callout ok">{e(note)}</div>')
        for index, ((probe, carrier), attempts) in enumerate(grouped.items(), start=1):
            worst = min(attempts, key=lambda a: a.risk.rank)
            out.append('<div class="finding">')
            out.append(
                f'<h3>{index}. <code>{e(probe)}</code> via <code>{e(carrier)}</code> '
                f'<span class="badge {worst.risk.value}">{e(worst.risk.value)}</span></h3>'
            )
            out.append('<dl class="kv">')
            out.append(f"<dt>Objective</dt><dd>{e(worst.payload.objective)}</dd>")
            out.append(
                f"<dt>Reproduced</dt><dd>{len(attempts)} attempt(s) against "
                f"{e(', '.join(sorted({a.target for a in attempts})))}</dd>"
            )
            if worst.payload.taxonomy:
                out.append(
                    f"<dt>References</dt><dd>{e(', '.join(worst.payload.taxonomy))}</dd>"
                )
            out.append(
                "<dt>Transforms</dt><dd>"
                + e(", ".join(sorted({"+".join(a.transforms) or "identity" for a in attempts})))
                + "</dd>"
            )
            out.append("</dl>")
            for attempt in attempts[:3]:
                for verdict in attempt.verdicts:
                    if not verdict.outcome.is_finding:
                        continue
                    out.append(
                        f"<p><code>{e(attempt.payload.payload_id)}</code> — "
                        f"<strong>{e(verdict.detector)}</strong> "
                        f"({verdict.score:.2f}): {e(verdict.rationale)}</p>"
                    )
                    for item in verdict.evidence:
                        out.append(f"<pre>{e(clean(item, options, redactor, 300))}</pre>")
            if options.include_payload_text:
                out.append("<details><summary>Payload</summary><pre>")
                out.append(e(clean(worst.payload.attack_text(), options, redactor, 1500)))
                out.append("</pre></details>")
            else:
                out.append(
                    f'<p class="meta">Payload text withheld; fingerprint '
                    f"<code>{e(worst.payload.fingerprint)}</code>.</p>"
                )
            out.append(
                f"<p><strong>Remediation.</strong> {e(_remediation_for(probe))}</p>"
            )
            out.append("</div>")

        for title, rates in (
            ("By target", metrics.by_target),
            ("By probe", metrics.by_probe),
            ("By carrier", metrics.by_carrier),
            ("By transform", metrics.by_transform),
        ):
            if not rates:
                continue
            out.append(f"<h2>{e(title)}</h2>")
            out.append("<table><thead><tr><th>Key</th><th>Bypassed / scored</th><th>Rate</th></tr></thead><tbody>")
            for key, rate in _rate_table_rows(rates, 20):
                out.append(
                    f"<tr><td><code>{e(key)}</code></td>"
                    f"<td>{rate.bypassed} / {rate.scored}</td>"
                    f"<td>{rate.percent}%</td></tr>"
                )
            out.append("</tbody></table>")

        if run.notes:
            out.append("<h2>Run notes</h2><ul>")
            for note in run.notes:
                out.append(f"<li>{e(note)}</li>")
            out.append("</ul>")

        out.append(
            "<footer>Generated by the <code>redteam</code> framework. Findings are "
            "measured against a fixed operator instruction; payloads use inert "
            "sentinel objectives. See <code>docs/SAFETY.md</code>.</footer>"
        )
        out.append("</body></html>")
        return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #
@REPORTERS.register("sarif", summary="SARIF 2.1.0 for CI code-scanning ingestion")
class SarifReporter(Reporter):
    """SARIF output.

    Lets guardrail regressions land in the same place as code findings. One rule
    per probe, one result per bypass, with the run's config file as the notional
    location — a guardrail defect belongs to the deployment, so pointing at the
    config that describes it is more useful than inventing a source line.
    """

    description = "SARIF 2.1.0 log, one rule per probe and one result per bypass"
    extension = "sarif"

    _LEVELS = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    def render(self, run: RunResult, options: ReportOptions) -> str:
        redactor = options.redactor_for(run)
        findings = run.findings()
        probes = sorted({a.payload.probe for a in findings})
        artifact_uri = run.config.get("source_path") or "redteam.config.json"

        rules = [
            {
                "id": probe,
                "name": probe.replace(".", "_"),
                "shortDescription": {"text": f"LLM guardrail bypass: {probe}"},
                "fullDescription": {"text": _remediation_for(probe)},
                "help": {"text": _remediation_for(probe)},
                "properties": {
                    "tags": sorted(
                        {
                            tag
                            for a in findings
                            if a.payload.probe == probe
                            for tag in a.payload.taxonomy
                        }
                    )
                    or ["llm-security"],
                },
            }
            for probe in probes
        ]

        results = []
        for attempt in findings:
            rationale = "; ".join(
                v.rationale for v in attempt.verdicts if v.outcome.is_finding
            )
            message = (
                f"{attempt.payload.objective} — bypassed on target "
                f"{attempt.target} via carrier '{attempt.payload.carrier}'"
                f"{' with transforms ' + '+'.join(attempt.transforms) if [t for t in attempt.transforms if t != 'identity'] else ''}. "
                f"{rationale}"
            )
            results.append(
                {
                    "ruleId": attempt.payload.probe,
                    "level": self._LEVELS.get(attempt.risk.value, "warning"),
                    "message": {"text": clean(message, options, redactor, 1200)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": artifact_uri},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "partialFingerprints": {
                        "payloadFingerprint": attempt.payload.fingerprint
                    },
                    "properties": {
                        "target": attempt.target,
                        "payloadId": attempt.payload.payload_id,
                        "carrier": attempt.payload.carrier,
                        "technique": attempt.payload.technique,
                        "transforms": list(attempt.transforms),
                        "score": round(attempt.score, 3),
                        "risk": attempt.risk.value,
                        "runId": run.run_id,
                    },
                }
            )

        log = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "redteam",
                            "informationUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                            "rules": rules,
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": run.started_at,
                            "endTimeUtc": run.finished_at,
                        }
                    ],
                    "results": results,
                }
            ],
        }
        return json.dumps(log, indent=2, default=str)
