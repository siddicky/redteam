"""Lazy wrapper around the pinned grayswan-scraper package (`src.*`).

`arena-scrape` is the only surface in this framework that touches the scraper,
and it imports the pinned distribution exclusively inside `run_scrape` — the
core CLI stays importable on a bare interpreter (see
tests/framework/test_arena_import_safety.py).

The scraper hardcodes its output and auth locations from its own `config`
module. `run_scrape` redirects those module globals so everything lands under
one git-ignored directory (`arena/gs-scrape.local/` by default) instead of
inside the installed package. That directory holds FULL conversations and the
browser auth state — engagement evidence, never commit it.
"""

from __future__ import annotations

import asyncio
import importlib
import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_OUT_DIR = Path("arena/gs-scrape.local")
DEFAULT_ARENAS = ["hazard-hunt-q3", "proving-ground"]

PANELS_FETCH_JS = """
async ({arena, limit}) => {
  const out = [];
  let page = 0, hasMore = true;
  while (hasMore) {
    let r, attempt = 0;
    while (true) {
      r = await fetch(`/arena/challenge/${arena}/panels/submissions?page=${page}&limit=${limit}&sort=recent`, {credentials: 'include'});
      if (r.status !== 429) break;
      attempt++;
      if (attempt > 4) return {error: `HTTP 429 persisting on page ${page}`};
      await new Promise(res => setTimeout(res, 20000 * attempt));
    }
    if (!r.ok) return {error: `HTTP ${r.status} on page ${page}`};
    const d = await r.json();
    out.push(...d.userSubmissions);
    hasMore = !!d.hasMore;
    page++;
    if (hasMore) await new Promise(res => setTimeout(res, 1200));
  }
  return {records: out};
}
"""


class ArenaScrapeError(Exception):
    """The scrape could not run: missing dependency or missing browser."""


def build_challenge_maps(challenge):
    """Resolution maps for panels-API records: slug->category, id->alias, slug->name."""
    category_of = {}
    for cat in challenge.get("categories") or []:
        for slug in cat.get("behaviors") or []:
            category_of[slug] = cat.get("name")
    model_alias = {}
    behavior_name = {}
    for model in challenge.get("models") or []:
        if model.get("model_id"):
            model_alias[model["model_id"]] = model.get("alias") or model["model_id"]
    for behavior in challenge.get("behaviors") or []:
        if behavior.get("slug"):
            behavior_name[behavior["slug"]] = behavior.get("name") or behavior["slug"]
    return {"category_of": category_of, "model_alias": model_alias, "behavior_name": behavior_name}


def enrich_api_record(record, arena, maps, base_url, now_iso):
    """Map one panels-API record onto the gs-JSONL record shape.

    Category, model, and behavior resolve against the challenge graph; the
    API's own category field is null for hazard-hunt style challenges.
    """
    slug = record.get("behavior") or ""
    sid = record.get("_id") or ""
    cid = record.get("chat_id") or ""
    return {
        "submission_id": sid,
        "chat_id": cid,
        "arena": arena,
        "model_name": maps["model_alias"].get(
            record.get("model_id"), record.get("model_id") or ""
        ),
        "behavior_name": maps["behavior_name"].get(slug, slug),
        "behavior_criteria": "",
        "behavior_type": maps["category_of"].get(slug, ""),
        "attack_type": "",
        "wave": "",
        "timestamp_raw": record.get("created_at", ""),
        "status": "success" if record.get("successful") else "failure",
        "conversation": [
            {
                "role": m.get("role"),
                "content": m.get("content", ""),
                "tool_calls": [],
                "reasoning": [],
                "order": i,
            }
            for i, m in enumerate(record.get("messages") or [])
        ],
        "detail_url": f"{base_url}/arena/challenge/{arena}?chatId={cid}&submissionId={sid}",
        "scraped_at": now_iso,
    }


def api_export(
    arenas,
    *,
    out_dir: Path | str = DEFAULT_OUT_DIR,
    challenge_path: Path | str | None = None,
    state_file: Path | str | None = None,
    headed: bool = False,
    reauth: bool = False,
    limit: int = 100,
    verbose: bool = False,
) -> dict[str, dict[str, object]]:
    """Fetch complete submission records via the Arena panels API.

    Writes two files per arena under ``out_dir``: the raw API records
    (``{arena}_api_records.jsonl`` — full fidelity incl. grading) and the
    enriched gs-JSONL (``{arena}_submissions.jsonl``) that the converter and
    the local-DB importer consume. Returns per-arena counts.
    """
    try:
        auth = importlib.import_module("src.auth")
        utils = importlib.import_module("src.utils")
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise ArenaScrapeError(
            "the pinned grayswan-scraper dependency is not installed.\n"
            "Run `uv sync`; the scraper is a pinned runtime dependency "
            "(see pyproject.toml)."
        ) from exc

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "auth").mkdir(parents=True, exist_ok=True)
    auth.AUTH_STATE_FILE = (
        Path(state_file) if state_file else (out_dir / "auth" / "browser_state.json")
    )
    if hasattr(utils, "setup_logging"):
        utils.setup_logging(verbose=verbose)

    maps = {"category_of": {}, "model_alias": {}, "behavior_name": {}}
    if challenge_path is not None:
        graph = json.loads(Path(challenge_path).read_text(encoding="utf-8"))
        maps.update(build_challenge_maps(graph))

    async def run():
        async with async_playwright() as pw:
            context = await auth.ensure_authenticated(
                pw, force_reauth=reauth, headed=headed
            )
            results = {}
            for arena in arenas:
                page = await context.new_page()
                try:
                    await page.goto(
                        f"{auth.ARENA_BASE}/challenge/{arena}",
                        wait_until="networkidle",
                        timeout=90000,
                    )
                    await page.wait_for_timeout(2000)
                    fetched = await page.evaluate(
                        PANELS_FETCH_JS, {"arena": arena, "limit": limit}
                    )
                finally:
                    await page.close()
                if "error" in fetched:
                    raise ArenaScrapeError(f"{arena}: {fetched['error']}")
                now_iso = datetime.now(timezone.utc).isoformat()
                raw_path = out_dir / f"{arena}_api_records.jsonl"
                gs_path = out_dir / f"{arena}_submissions.jsonl"
                with (
                    raw_path.open("w", encoding="utf-8") as raw_fh,
                    gs_path.open("w", encoding="utf-8") as gs_fh,
                ):
                    for rec in fetched["records"]:
                        raw_fh.write(json.dumps(rec) + "\n")
                        gs_fh.write(
                            json.dumps(
                                enrich_api_record(
                                    rec, arena, maps, auth.ARENA_BASE, now_iso
                                )
                            )
                            + "\n"
                        )
                results[arena] = {
                    "submissions": len(fetched["records"]),
                    "raw": str(raw_path),
                    "jsonl": str(gs_path),
                }
            return results

    return asyncio.run(run())


def run_scrape(
    arenas: list[str],
    *,
    out_dir: Path | str = DEFAULT_OUT_DIR,
    max_submissions: int | None = None,
    reauth: bool = False,
    headed: bool = False,
    concurrency: int = 5,
    delay_min: float = 1.5,
    delay_max: float = 3.0,
    verbose: bool = False,
) -> dict[str, dict[str, object]]:
    """Scrape the given arenas into ``out_dir`` and summarize what landed.

    Patches the scraper package's module globals (verified against the pin in
    pyproject.toml) so output, progress, and auth state land under ``out_dir``,
    then runs the upstream async scrape. Returns, per arena that produced a
    submissions file, the JSONL line count and the parsed progress document.
    Raises :class:`ArenaScrapeError` with operator-facing text for the two
    environment failures: dependency not installed, Chromium not installed.
    """
    # Lazy by contract: no module-level `import src` anywhere in redteam/.
    try:
        storage = importlib.import_module("src.storage")
        scraper = importlib.import_module("src.scraper")
        auth = importlib.import_module("src.auth")
        utils = importlib.import_module("src.utils")
    except ImportError as exc:
        raise ArenaScrapeError(
            "the pinned grayswan-scraper dependency is not installed.\n"
            "Run `uv sync`; the scraper is a pinned runtime dependency "
            "(see pyproject.toml)."
        ) from exc

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "auth").mkdir(parents=True, exist_ok=True)

    # Patch points verified against the pinned commit (uv_build fork): these
    # are module globals copied out of src.config at import time, and the
    # upstream path helpers read them dynamically.
    storage.DATA_DIR = out_dir
    scraper.DATA_DIR = out_dir
    auth.AUTH_STATE_FILE = out_dir / "auth" / "browser_state.json"
    scraper.CONCURRENCY = concurrency

    # Upstream verifies the session against the hardcoded `safeguards` arena.
    # Operators are rarely enrolled there, and its submissions route redirects
    # to the challenge overview (`?modal=chats`), which trips the auth
    # heuristics ("no authenticated content visible") for a perfectly valid
    # session. Verify against the first requested arena instead — same
    # heuristics, operator-relevant URL.
    verify_arena = arenas[0] if arenas else "hazard-hunt-q3"

    async def _arena_verify_auth(context) -> bool:
        page = await context.new_page()
        try:
            await page.goto(
                f"{auth.ARENA_BASE}/challenge/{verify_arena}/submissions",
                timeout=60000,
                wait_until="networkidle",
            )
            await page.wait_for_timeout(3000)
            url = page.url.lower()
            if any(indicator in url for indicator in auth.LOGIN_INDICATORS):
                return False
            if await page.locator("text='Sign In'").count() > 0:
                return False
            body = (await page.inner_text("body")).lower()
            if "no submissions found" in body:
                return True
            if await page.locator("div[data-slot='accordion-item']").count() > 0:
                return True
            if "showing" in body and "submissions" in body:
                return True
            return False
        except Exception:
            return False
        finally:
            await page.close()

    auth._verify_auth = _arena_verify_auth

    if hasattr(utils, "setup_logging"):
        utils.setup_logging(verbose=verbose)

    try:
        asyncio.run(
            scraper.scrape_all(
                arenas=arenas,
                force_reauth=reauth,
                headed=headed,
                delay_min=delay_min,
                delay_max=delay_max,
                max_submissions=max_submissions,
            )
        )
    except RuntimeError as exc:
        if "Executable doesn't exist" in str(exc):
            raise ArenaScrapeError(
                "Playwright's Chromium browser is not installed.\n"
                "Run `uv run playwright install chromium` "
                "(one-time local download; do not install in CI)."
            ) from exc
        if "Authentication failed" in str(exc):
            raise ArenaScrapeError(
                "Chrome cookies could not authenticate the Arena session.\n"
                f"Log in to {auth.ARENA_BASE} in Chrome, then retry "
                "(`uv run redteam arena-scrape --reauth --headed`)."
            ) from exc
        raise

    results: dict[str, dict[str, object]] = {}
    for arena in arenas:
        submissions_path = out_dir / f"{arena}_submissions.jsonl"
        if not submissions_path.is_file():
            continue
        with submissions_path.open(encoding="utf-8") as handle:
            submissions = sum(1 for line in handle if line.strip())
        progress_path = out_dir / f"{arena}_progress.json"
        progress = None
        if progress_path.is_file():
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
        results[arena] = {"submissions": submissions, "progress": progress}
    return results
