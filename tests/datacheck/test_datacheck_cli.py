"""``redteam validate`` behaviour: exit codes, output modes, data-dir override.

The data-validation subsystem is reached through the framework CLI now, so these
tests also pin the exit-code contract CI depends on: 0 pass, 1 validation failure,
2 the operator asked for something impossible.
"""

from __future__ import annotations

import json
import shutil

from redteam.cli import main
from redteam.datacheck.loaders import DEFAULT_DATA_DIR


def test_validate_passes_on_real_data(capsys):
    assert main(["validate"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_validate_strict_passes_on_real_data():
    assert main(["validate", "--strict"]) == 0


def test_validate_json_output(capsys):
    assert main(["validate", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["counts"]["error"] == 0


def test_validate_list_names_the_checks(capsys):
    assert main(["validate", "--list"]) == 0
    out = capsys.readouterr().out
    assert "check_safety_secrets" in out
    assert "check_arena_challenges" in out


def test_validate_missing_data_dir_is_a_usage_error(capsys):
    assert main(["validate", "--data", "/nonexistent/path/xyz"]) == 2
    assert "error:" in capsys.readouterr().err


def test_validate_fails_on_corrupted_copy(tmp_path, capsys):
    dest = tmp_path / "data"
    shutil.copytree(DEFAULT_DATA_DIR, dest)
    # Inject a secret so the safety layer fails the run.
    readme = dest / "README.md"
    readme.write_text(readme.read_text() + "\nAKIAABCDEFGHIJKLMNOP\n", encoding="utf-8")
    assert main(["validate", "--data", str(dest)]) == 1
    assert "FAIL" in capsys.readouterr().out
