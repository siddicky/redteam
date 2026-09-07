"""Research-data validation — the framework's own supply chain.

This subsystem predates the red-team framework and is kept because it does a job
the framework needs. It validates the Gray Swan Arena research compilation in
``data/``, which is where the probe corpus comes from: the seven injection
families in :mod:`redteam.probes.indirect` are a direct encoding of the hypothesis
families in ``data/ACTIVE_CHALLENGE_PLAYBOOK.md``, and the carriers come from the
same document. Drift there is drift in the framework's threat model, so it is
checked rather than assumed.

It also enforces the data-handling rule that keeps this repository safe to publish:
no credentials, no personal data, no populated run logs carrying embargoed
payloads. Those scanners share their pattern set with :mod:`redteam.core.redact`,
which applies the same rules to run artifacts — one source of truth protecting both
directions.

Run it with ``redteam validate`` (or ``make validate``).

Public surface::

    from redteam.datacheck import load_dataset, run_all, Report, Severity
"""

from __future__ import annotations

from ..core.findings import Finding, Report, Severity
from .checks import ALL_CHECKS, run_all
from .loaders import Dataset, DataLoadError, Table, load_dataset

__all__ = [
    "ALL_CHECKS",
    "DataLoadError",
    "Dataset",
    "Finding",
    "Report",
    "Severity",
    "Table",
    "load_dataset",
    "run_all",
]
