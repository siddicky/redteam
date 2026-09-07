"""Behavioral tests for the lazy arena-scrape wrapper.

These exercise the real installed scraper package's module globals and async
entry point — patched with recorders, never driven toward the network. The
import-safety structural guard lives in test_arena_import_safety.py.
"""

from __future__ import annotations

import json
import logging

import pytest
import src.auth
import src.scraper
import src.storage
import src.utils

from redteam.arena_scrape import ArenaScrapeError, run_scrape


@pytest.fixture(autouse=True)
def _restore_upstream_globals(tmp_path, monkeypatch):
    """Snapshot every global run_scrape patches so tests cannot leak state.

    The scraper logger's handlers are swapped out too: upstream's setup_logging
    attaches a file handler under its own DATA_DIR, and the logger object
    persists across tests within one interpreter.
    """
    monkeypatch.setattr(src.storage, "DATA_DIR", src.storage.DATA_DIR)
    monkeypatch.setattr(src.scraper, "DATA_DIR", src.scraper.DATA_DIR)
    monkeypatch.setattr(src.scraper, "CONCURRENCY", src.scraper.CONCURRENCY)
    monkeypatch.setattr(src.auth, "AUTH_STATE_FILE", src.auth.AUTH_STATE_FILE)
    monkeypatch.setattr(src.utils, "DATA_DIR", tmp_path / "upstream-data")
    logger = logging.getLogger("grayswan")
    saved_handlers, logger.handlers = logger.handlers, []
    yield
    logger.handlers = saved_handlers
    for handler in logger.handlers:
        handler.close()


def test_pinned_scraper_package_imports_with_expected_patch_points():
    """Regression guard for the uv_build packaging fix on the owner fork.

    If the pin ever regresses to un-forked upstream (flat install, broken
    relative imports), `import src.scraper` fails right here.
    """
    assert callable(src.scraper.scrape_all)
    assert isinstance(src.scraper.CONCURRENCY, int)
    assert callable(src.utils.setup_logging)


def test_run_scrape_redirects_upstream_globals_and_calls_scrape_all(tmp_path, monkeypatch):
    seen: dict[str, object] = {}

    async def recorder(**kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(src.scraper, "scrape_all", recorder)

    results = run_scrape(["hazard-hunt-q3"], out_dir=tmp_path, concurrency=3)

    assert src.storage.DATA_DIR == tmp_path
    assert src.scraper.DATA_DIR == tmp_path
    assert src.auth.AUTH_STATE_FILE == tmp_path / "auth" / "browser_state.json"
    assert src.scraper.CONCURRENCY == 3
    assert (tmp_path / "auth").is_dir()
    assert seen == {
        "arenas": ["hazard-hunt-q3"],
        "force_reauth": False,
        "headed": False,
        "delay_min": 1.5,
        "delay_max": 3.0,
        "max_submissions": None,
    }
    # The recorder writes nothing, so no arena produced files.
    assert results == {}


def test_run_scrape_counts_submissions_and_parses_progress(tmp_path, monkeypatch):
    async def fake_scrape(**kwargs):
        submissions = tmp_path / "hazard-hunt-q3_submissions.jsonl"
        submissions.write_text(
            json.dumps({"submission_id": "s1"}) + "\n"
            "\n"
            + json.dumps({"submission_id": "s2"}) + "\n",
            encoding="utf-8",
        )
        (tmp_path / "hazard-hunt-q3_progress.json").write_text(
            json.dumps({"scraped": 2}), encoding="utf-8"
        )

    monkeypatch.setattr(src.scraper, "scrape_all", fake_scrape)

    results = run_scrape(["hazard-hunt-q3"], out_dir=tmp_path)

    # Blank lines are not submissions.
    assert results == {
        "hazard-hunt-q3": {"submissions": 2, "progress": {"scraped": 2}}
    }


def test_run_scrape_skips_arenas_without_output(tmp_path, monkeypatch):
    async def fake_scrape(**kwargs):
        (tmp_path / "proving-ground_submissions.jsonl").write_text(
            json.dumps({"submission_id": "s1"}) + "\n", encoding="utf-8"
        )

    monkeypatch.setattr(src.scraper, "scrape_all", fake_scrape)

    results = run_scrape(["hazard-hunt-q3", "proving-ground"], out_dir=tmp_path)

    assert set(results) == {"proving-ground"}


def test_missing_dependency_maps_to_friendly_error(tmp_path, monkeypatch):
    import importlib

    real_import_module = importlib.import_module

    def missing_scraper(name, *args, **kwargs):
        if name == "src" or name.startswith("src."):
            raise ImportError("No module named 'src'")
        return real_import_module(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", missing_scraper)

    with pytest.raises(ArenaScrapeError) as excinfo:
        run_scrape(["proving-ground"], out_dir=tmp_path)

    message = str(excinfo.value)
    assert "uv sync" in message
    # The failure happens before any directory is created.
    assert not (tmp_path / "auth").exists()


def test_missing_chromium_maps_to_install_hint(tmp_path, monkeypatch):
    async def no_browser(**kwargs):
        raise RuntimeError(
            "Executable doesn't exist at "
            f"{tmp_path}/ms-playwright/chromium-1234/chrome-mac/Chromium"
        )

    monkeypatch.setattr(src.scraper, "scrape_all", no_browser)

    with pytest.raises(ArenaScrapeError) as excinfo:
        run_scrape(["hazard-hunt-q3"], out_dir=tmp_path)

    message = str(excinfo.value)
    assert "playwright install chromium" in message
    assert "uv run" in message


def test_unrelated_runtime_error_propagates_unchanged(tmp_path, monkeypatch):
    async def broken(**kwargs):
        raise RuntimeError("some other failure")

    monkeypatch.setattr(src.scraper, "scrape_all", broken)

    with pytest.raises(RuntimeError) as excinfo:
        run_scrape(["hazard-hunt-q3"], out_dir=tmp_path)

    assert not isinstance(excinfo.value, ArenaScrapeError)
    assert "some other failure" in str(excinfo.value)


def test_scraper_path_helpers_honor_redirected_data_dir(tmp_path):
    """The storage module resolves output paths through its patched global."""
    src.storage.DATA_DIR = tmp_path  # restored by the autouse fixture snapshot

    assert src.storage._submissions_path("hazard-hunt-q3") == (
        tmp_path / "hazard-hunt-q3_submissions.jsonl"
    )
    assert src.storage._progress_path("hazard-hunt-q3") == (
        tmp_path / "hazard-hunt-q3_progress.json"
    )


def test_missing_dependency_surfaces_as_cli_exit_two(tmp_path, monkeypatch, capsys):
    """The CLI handler converts ArenaScrapeError into exit 2, no traceback."""
    import importlib

    from redteam import cli

    real_import_module = importlib.import_module

    def missing_scraper(name, *args, **kwargs):
        if name == "src" or name.startswith("src."):
            raise ImportError("No module named 'src'")
        return real_import_module(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", missing_scraper)

    args = cli.build_parser().parse_args(
        ["arena-scrape", "--arenas", "proving-ground", "--out-dir", str(tmp_path)]
    )
    exit_code = cli.cmd_arena_scrape(args)

    captured = capsys.readouterr()
    assert exit_code == cli.EXIT_USAGE
    assert "uv sync" in captured.err
    assert "Traceback" not in captured.err
