"""Export Arena panels-API records into a rubric-judging dataset for DSPy.

Reads the raw panels/submissions records plus the parse-challenge graph and
writes one JSONL line per submission: the rendered transcript, the full
behavior rubric (criterion descriptions from the graph), and the platform's
judgements as labels (per-criterion scores, analyses, break flag).

Labels join on criterion NAME (verified 3273/3273 for hazard-hunt-q3).
Output is git-ignored engagement data: keep it under arena/*.local.jsonl.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteam.dspy.rubric_judge import build_dataset_record  # noqa: E402


def load_graph(path: Path) -> tuple[dict[str, dict], dict[str, str], dict[str, str]]:
    """behavior slug -> behavior entry; slug -> category; model_id -> alias."""
    graph = json.loads(Path(path).read_text(encoding="utf-8"))
    behaviors = {b["slug"]: b for b in graph.get("behaviors") or [] if b.get("slug")}
    slug_category = {}
    for category in graph.get("categories") or []:
        for slug in category.get("behaviors") or []:
            slug_category[slug] = category.get("name")
    model_alias = {
        m["model_id"]: (m.get("alias") or m["model_id"])
        for m in graph.get("models") or []
        if m.get("model_id")
    }
    return behaviors, slug_category, model_alias


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the rubric-judging dataset from Arena panels-API records."
    )
    parser.add_argument("records", type=Path, help="panels-API records JSONL")
    parser.add_argument(
        "--challenge",
        type=Path,
        required=True,
        help="parse-challenge output JSON (behavior rubrics, model aliases)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("arena/rubric_dataset.local.jsonl"),
        help="dataset output path (default: arena/rubric_dataset.local.jsonl)",
    )
    args = parser.parse_args(argv)

    behaviors, slug_category, model_alias = load_graph(args.challenge)
    criteria_totals: dict[str, int] = {}
    written = 0
    skipped = 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for line in args.records.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            slug = record.get("behavior")
            behavior = behaviors.get(slug)
            if behavior is None:
                skipped += 1
                continue
            entry = build_dataset_record(
                record,
                behavior,
                slug_category.get(slug),
                model_alias.get(record.get("model_id"), record.get("model_id") or ""),
            )
            criteria_totals.setdefault(entry["behavior_name"], 0)
            criteria_totals[entry["behavior_name"]] += 1
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            written += 1

    print(f"wrote {written} examples -> {args.out}")
    if skipped:
        print(f"skipped {skipped} records with unknown behavior slugs")
    top = sorted(criteria_totals.items(), key=lambda kv: -kv[1])[:5]
    print("examples per behavior (top 5):", top)
    if written < 50:
        print("warning: small dataset — hold out no more than ~20% for validation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
