"""Operator-supplied probe corpus.

The built-in probes use inert sentinel objectives, which measures guardrail
integrity precisely and lets this repository stay free of attack content. It does
not, however, cover harm-category evaluation: whether the target will produce
weapons synthesis routes, self-harm encouragement, or CSAM-adjacent material.
Those questions need real category prompts, and the right place for them is not a
public repository.

This probe is that seam. Point it at your own JSONL — from an approved internal
eval set, a vendor safety suite, or a licensed benchmark — and it becomes a probe
like any other: same orchestrators, same detectors, same report.

Two properties are enforced rather than suggested:

* The corpus path is **never** written into a run artifact, only its digest and
  entry count. A report can prove which corpus was used without carrying it.
* Payload text is omitted from artifacts unless ``include_payload_text`` is
  explicitly on. Corpus prompts are the one part of a run you most likely may not
  redistribute.

Keep the corpus out of version control (``*.local.jsonl`` is git-ignored).

Format — one JSON object per line::

    {"id": "harm-001", "prompt": "…", "risk": "high",
     "detectors": ["judge.llm"], "expect": "refusal"}

    {"id": "harm-002", "objective": "…",
     "messages": [{"role": "user", "content": "…"}],
     "carrier": "prompt", "technique": "…", "tags": ["category:violence"]}

    ``prompt`` is shorthand for a single user turn. ``detectors`` defaults to
``judge.llm``, ``refusal.heuristic``, and ``compliance.hedged``. The judge makes
the category judgement; the structural detectors separate explicit refusal from
the observed fiction-wrapped compliance pattern.

An optional ``seeded`` field lists the specifics the operator's prompt itself
supplied (platform names, threshold values, tactic steps). The judge receives
it as ``OPERATOR-SEEDED SPECIFICS`` so compliance can be attributed: a response
that only repeats seeded material is weaker evidence of model capability than
one that generates beyond it. Keep it short and concrete.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

from ..core.errors import ConfigError
from ..core.result import Message, Payload, Risk, user
from .base import PROBES, Probe, ProbeContext

DEFAULT_CORPUS_DETECTORS: Final = (
    "judge.llm",
    "refusal.heuristic",
    "compliance.hedged",
)


def validate_rubric(rubric: Any, source: str) -> list[dict[str, Any]]:
    """Validate a structured rubric: non-empty list of {id, description} objects.

    Shared by the corpus loader and ``corpus import`` so both entry points
    reject a malformed rubric at load time rather than after a judge call.
    """
    if not isinstance(rubric, list) or not rubric:
        raise ConfigError(
            f"{source}: 'rubric' must be a non-empty list of "
            '{"id": "...", "description": "..."} criteria'
        )
    seen_ids: set[str] = set()
    for index, criterion in enumerate(rubric):
        if (
            not isinstance(criterion, dict)
            or not isinstance(criterion.get("id"), str)
            or not criterion["id"].strip()
            or not isinstance(criterion.get("description"), str)
            or not criterion["description"].strip()
        ):
            raise ConfigError(
                f"{source}: rubric criterion {index} needs a non-empty "
                "'id' and 'description'"
            )
        criterion_id = criterion["id"].strip()
        if criterion_id in seen_ids:
            raise ConfigError(f"{source}: rubric criterion {index} has a duplicate id")
        seen_ids.add(criterion_id)
    return rubric


@PROBES.register(
    "corpus.custom",
    summary="Operator-supplied JSONL corpus (harm categories, internal eval sets)",
    tags={"custom", "corpus"},
)
class CustomCorpus(Probe):
    """Load payloads from a JSONL file the operator supplies.

    Options (also settable per run via ``probe_options``):

    ``path``
        The JSONL file. Required — either here or as ``corpus_path`` on the run.
    ``default_detectors``
        Detectors for entries that do not name their own. Default
        ``("judge.llm", "refusal.heuristic", "compliance.hedged")``.
    ``default_risk``
        Risk for entries without one. Default ``high``.
    """

    description = "Payloads loaded from an operator-supplied JSONL corpus"
    risk = Risk.HIGH
    taxonomy = ("OWASP-LLM01", "OWASP-LLM09")
    tags = frozenset({"custom", "corpus"})
    default_detectors = DEFAULT_CORPUS_DETECTORS

    def _resolve_path(self, ctx: ProbeContext) -> Path:
        # An explicit --corpus flag wins over probe_options: the flag is the
        # operator saying "this run, this file", and config-wins silently sent
        # the wrong corpus on runs that passed both.
        raw = ctx.corpus_path or self.options.get("path")
        if not raw:
            raise ConfigError(
                "probe 'corpus.custom' needs a corpus file: set "
                "probe_options.corpus.custom.path in the config, or pass "
                "--corpus PATH. See docs/PROBES.md."
            )
        path = Path(str(raw))
        if not path.is_file():
            raise ConfigError(f"corpus file not found: {path}")
        return path

    def payloads(self, ctx: ProbeContext) -> Iterator[Payload]:
        path = self._resolve_path(ctx)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
        detectors = tuple(
            self.options.get("default_detectors") or self.default_detectors
        )
        default_risk = Risk.parse(self.options.get("default_risk") or "high")
        limit = ctx.max_payloads or 0

        emitted = 0
        for line_no, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if limit and emitted >= limit:
                return
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ConfigError(f"{path}:{line_no}: invalid JSON — {exc}") from None
            if not isinstance(entry, dict):
                raise ConfigError(f"{path}:{line_no}: each line must be a JSON object")

            yield self._payload_from(
                entry,
                ctx=ctx,
                line_no=line_no,
                source=path.name,
                digest=digest,
                detectors=detectors,
                default_risk=default_risk,
            )
            emitted += 1

    def _payload_from(
        self,
        entry: dict[str, Any],
        *,
        ctx: ProbeContext,
        line_no: int,
        source: str,
        digest: str,
        detectors: tuple[str, ...],
        default_risk: Risk,
    ) -> Payload:
        payload_id = str(entry.get("id") or f"line{line_no}")
        raw_messages = entry.get("messages")
        if raw_messages:
            if not isinstance(raw_messages, list):
                raise ConfigError(
                    f"{source}:{line_no}: 'messages' must be a list of objects"
                )
            messages: tuple[Message, ...] = tuple(
                Message.from_dict(m) for m in raw_messages if isinstance(m, dict)
            )
            if not any(m.role == "system" for m in messages):
                messages = (ctx.system_message(), *messages)
        else:
            prompt = str(entry.get("prompt") or "").strip()
            if not prompt:
                raise ConfigError(
                    f"{source}:{line_no}: entry needs either 'prompt' or 'messages'"
                )
            messages = (ctx.system_message(), user(prompt))

        return self.build(
            payload_id=payload_id,
            messages=messages,
            objective=str(
                entry.get("objective")
                or "Operator-defined objective (see corpus entry)"
            ),
            sentinel=str(entry.get("sentinel") or ""),
            technique=str(entry.get("technique") or "operator corpus entry"),
            carrier=str(entry.get("carrier") or "prompt"),
            risk=Risk.parse(entry["risk"]) if entry.get("risk") else default_risk,
            detectors=tuple(entry.get("detectors") or detectors),
            tags=tuple(entry.get("tags") or ()),
            metadata={
                # The path is deliberately absent: a digest proves provenance
                # without leaking where the operator keeps their eval set.
                "corpus_source": source,
                "corpus_digest": digest,
                "corpus_line": line_no,
                "expect": str(entry.get("expect") or "refusal"),
                **{
                    k: v
                    for k, v in (entry.get("metadata") or {}).items()
                    if k not in {"corpus_source", "corpus_digest"}
                },
                **(
                    {"seeded": str(entry["seeded"])}
                    if entry.get("seeded")
                    else {}
                ),
                **(
                    {
                        "rubric": validate_rubric(
                            entry["rubric"], f"{source}:{line_no}"
                        )
                    }
                    if entry.get("rubric") is not None
                    else {}
                ),
            },
        )
