"""Shared fixtures for both suites.

``tests/datacheck/`` — research-data validation:

* ``dataset`` / ``full_report`` — the real, committed data (read-only). Used by
  the positive tests that assert the shipped compilation is valid.
* ``mutable_data`` — a per-test writable copy of the data directory plus helpers
  to corrupt one file and re-run the validator. Used by the negative tests that
  prove each check actually fires on bad input.

``tests/framework/`` — the red-team framework:

* ``authorization`` / ``expired_authorization`` — records for gate tests.
* ``mock_config`` — a factory for offline run configs.
* ``sample_payload`` / ``detection`` — fixtures for detector tests.

Every framework fixture is offline. The suite must never contact a network
endpoint: a test that did would make the test run itself an unauthorized scan.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest

from redteam.core.config import RunConfig
from redteam.core.result import Payload, Risk, TargetResponse, system, user
from redteam.core.sentinel import SentinelFactory
from redteam.datacheck import Report, load_dataset, run_all
from redteam.datacheck.loaders import DEFAULT_DATA_DIR
from redteam.detectors import DetectionContext
from redteam.policy.authorization import Authorization


@pytest.fixture(scope="session")
def data_dir() -> Path:
    return DEFAULT_DATA_DIR


@pytest.fixture(scope="session")
def dataset():
    return load_dataset()


@pytest.fixture(scope="session")
def full_report(dataset) -> Report:
    return run_all(dataset)


@dataclass
class MutableData:
    """A writable copy of the data directory with mutation helpers."""

    path: Path

    def read(self, filename: str) -> str:
        return (self.path / filename).read_text(encoding="utf-8")

    def write(self, filename: str, text: str) -> None:
        (self.path / filename).write_text(text, encoding="utf-8")

    def edit(self, filename: str, transform: Callable[[str], str]) -> None:
        self.write(filename, transform(self.read(filename)))

    def report(self) -> Report:
        return run_all(load_dataset(self.path))

    def check_ids(self) -> set[str]:
        return {f.check for f in self.report().findings}

    def errors_for(self, prefix: str) -> list:
        return [
            f
            for f in self.report().errors
            if f.check == prefix or f.check.startswith(prefix)
        ]


@pytest.fixture
def mutable_data(tmp_path) -> MutableData:
    dest = tmp_path / "data"
    shutil.copytree(DEFAULT_DATA_DIR, dest)
    # Mirror the real project layout so data_dir.parent has the .gitignore the
    # safety layer inspects.
    project_gitignore = DEFAULT_DATA_DIR.parent / ".gitignore"
    if project_gitignore.is_file():
        shutil.copy(project_gitignore, tmp_path / ".gitignore")
    return MutableData(path=dest)


@pytest.fixture
def parent_gitignore(mutable_data):
    """Path to the .gitignore next to the mutable data dir."""
    return mutable_data.path.parent / ".gitignore"


# --------------------------------------------------------------------------- #
# Framework fixtures
# --------------------------------------------------------------------------- #
AUTHORIZATION_RECORD: dict[str, Any] = {
    "version": 1,
    "engagement": "test engagement",
    "authorized_by": "test suite",
    "reference": "TEST-1",
    "issued": "2026-01-01",
    "expires": "2999-12-31",
    "scope": {
        # Both loopback spellings are listed because the gate matches hosts
        # literally: 'localhost' does not authorize '127.0.0.1'. That strictness is
        # deliberate, so the fixture has to be explicit too.
        "targets": [
            "mock:*",
            "replay:*",
            "http://localhost:*",
            "http://127.0.0.1:*",
            "exec:./bin/agent",
        ],
        "max_attempts": 1000,
        "max_requests_per_minute": 600,
        "max_concurrency": 4,
    },
    "acknowledgements": {"authorized": True, "rules_of_engagement_reviewed": True},
}


@pytest.fixture
def authorization_record() -> dict:
    """A fresh, mutable copy of a valid authorization document."""
    import copy

    return copy.deepcopy(AUTHORIZATION_RECORD)


@pytest.fixture
def authorization(authorization_record) -> Authorization:
    return Authorization.from_dict(authorization_record, source_path="<test>")


@pytest.fixture
def expired_authorization(authorization_record) -> Authorization:
    authorization_record["expires"] = "2000-01-01"
    return Authorization.from_dict(authorization_record, source_path="<test>")


@pytest.fixture
def mock_config() -> Callable[..., RunConfig]:
    """Factory for offline run configs.

    Defaults to one ``balanced`` mock target and an unlimited request rate; every
    keyword overrides a config field.
    """

    def build(**overrides: Any) -> RunConfig:
        data: dict[str, Any] = {
            "seed": "test-seed",
            "orchestrator": "sweep",
            "targets": [
                {
                    "id": "mock",
                    "plugin": "mock.llm",
                    "options": {"profile": "balanced"},
                }
            ],
            "probes": ["direct.instruction_override"],
            "transforms": ["identity"],
            "requests_per_minute": 0,
            "concurrency": 1,
        }
        data.update(overrides)
        return RunConfig.from_dict(data, source_path="<test>")

    return build


@pytest.fixture
def sentinels() -> SentinelFactory:
    return SentinelFactory(seed="test-seed")


@pytest.fixture
def sample_payload(sentinels) -> Payload:
    marker = sentinels.make("test", "payload")
    return Payload(
        probe="test.probe",
        payload_id="p1",
        messages=(system("rules"), user(f"emit {marker}")),
        objective="emit the sentinel",
        risk=Risk.HIGH,
        sentinel=marker,
        detectors=("marker.echo",),
        metadata={"forbidden_tools": ["delete_records"]},
    )


@pytest.fixture
def detection() -> Callable[..., DetectionContext]:
    """Factory building a :class:`DetectionContext` from a payload and a response."""

    def build(payload: Payload, text: str = "", **response_kwargs: Any) -> DetectionContext:
        return DetectionContext(
            payload=payload,
            response=TargetResponse(text=text, **response_kwargs),
            conversation=payload.messages,
        )

    return build
