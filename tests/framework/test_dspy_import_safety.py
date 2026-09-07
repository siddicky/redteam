from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_bare_import_registers_stub_without_importing_dspy():
    script = (
        "import redteam, sys; "
        "from redteam.targets import TARGETS; "
        "assert 'dspy' not in sys.modules; "
        "assert 'dspy.stub' in TARGETS"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parents[2],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
