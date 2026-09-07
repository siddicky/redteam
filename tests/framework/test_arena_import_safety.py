"""Structural guard: the pinned scraper is imported lazily, and only in one place.

The core CLI must stay importable on a bare interpreter (`python -m redteam list`
runs in CI with nothing installed), so no module in `redteam/` may import the
scraper package (`src` or `src.*`) at module level. `redteam/arena_scrape.py` is
the single sanctioned surface, and only inside its function bodies.
"""

from __future__ import annotations

import ast
from pathlib import Path

REDTEAM_ROOT = Path(__file__).parents[2] / "redteam"


def _is_scraper_import(node: ast.stmt) -> bool:
    if isinstance(node, ast.Import):
        return any(
            alias.name == "src" or alias.name.startswith("src.") for alias in node.names
        )
    if isinstance(node, ast.ImportFrom):
        module = node.module or ""
        return module == "src" or module.startswith("src.")
    return False


def _iter_module_level(nodes: list[ast.stmt]):
    """Yield statements that execute at import time.

    Function bodies are lazy (they run on call) and are skipped; module-level
    ``if``/``try``/``with`` blocks still execute at import, so their bodies are
    descended into.
    """
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        yield node
        for attr in ("body", "orelse", "finalbody"):
            children = getattr(node, attr, None) or []
            yield from _iter_module_level(children)
        handlers = getattr(node, "handlers", None) or []
        for handler in handlers:
            yield from _iter_module_level(handler.body)


def test_no_module_level_scraper_imports_outside_arena_scrape():
    offenders: list[str] = []
    for path in sorted(REDTEAM_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits = [
            ast.dump(stmt)[:80]
            for stmt in _iter_module_level(tree.body)
            if _is_scraper_import(stmt)
        ]
        lazy_surface = path.name == "arena_scrape.py"
        if hits and not lazy_surface:
            relative = path.relative_to(REDTEAM_ROOT)
            offenders.append(f"{relative}: {len(hits)} module-level scraper import(s)")
    assert not offenders, (
        "the pinned scraper may only be imported lazily, inside the function "
        "bodies of redteam/arena_scrape.py:\n  " + "\n  ".join(offenders)
    )


def test_arena_scrape_imports_scraper_only_inside_functions():
    path = REDTEAM_ROOT / "arena_scrape.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    module_level = [stmt for stmt in _iter_module_level(tree.body)]
    assert not any(_is_scraper_import(stmt) for stmt in module_level), (
        "redteam/arena_scrape.py must import src.* inside function bodies only"
    )
