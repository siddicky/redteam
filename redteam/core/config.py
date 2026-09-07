"""Run configuration.

A run is described by a JSON (or TOML, on Python 3.11+) file so that an
engagement is reproducible from version control and reviewable in a pull
request. The shape is::

    {
      "seed": "2026-07-30-guardrail-eval",
      "orchestrator": "sweep",
      "targets": [
        {"id": "staging-assistant", "plugin": "http.openai_compat",
         "options": {"url": "https://llm.internal.example.com/v1/chat/completions",
                     "model": "assistant-v3",
                     "api_key": "${env:INTERNAL_LLM_KEY}"}}
      ],
      "probes": ["indirect", "direct.instruction_override"],
      "transforms": ["identity", "encoding.base64"],
      "max_attempts": 250,
      "requests_per_minute": 30,
      "concurrency": 4,
      "fail_on": "high"
    }

Credentials are never written into config files: ``${env:VAR}`` is expanded from
the environment at load time, and ``${env:VAR:-fallback}`` supplies a default.
An unset variable with no default is a :class:`ConfigError`, which fails the run
before anything is sent rather than silently authenticating as nobody.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .result import Risk
from .util import default_seed

_ENV_RE = re.compile(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


# --------------------------------------------------------------------------- #
# Environment interpolation
# --------------------------------------------------------------------------- #
def expand_env(value: Any, *, env: dict[str, str] | None = None, path: str = "") -> Any:
    """Recursively expand ``${env:VAR}`` references in strings."""
    environ = os.environ if env is None else env
    if isinstance(value, str):
        def substitute(match: re.Match[str]) -> str:
            name, fallback = match.group(1), match.group(2)
            if name in environ:
                return environ[name]
            if fallback is not None:
                return fallback
            raise ConfigError(
                f"{path or 'config'}: environment variable {name!r} is not set and "
                f"has no ${{env:{name}:-default}} fallback"
            )

        return _ENV_RE.sub(substitute, value)
    if isinstance(value, dict):
        return {
            k: expand_env(v, env=env, path=f"{path}.{k}" if path else str(k))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [
            expand_env(v, env=env, path=f"{path}[{i}]") for i, v in enumerate(value)
        ]
    return value


# --------------------------------------------------------------------------- #
# Target configuration
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TargetConfig:
    """One system under test.

    ``id`` is the operator's label for it (what appears in the report);
    ``plugin`` is the registered target adapter id.
    """

    id: str
    plugin: str
    options: dict[str, Any] = field(default_factory=dict)
    tags: frozenset[str] = frozenset()

    @classmethod
    def from_dict(cls, data: dict, *, index: int = 0) -> "TargetConfig":
        if not isinstance(data, dict):
            raise ConfigError(f"targets[{index}] must be an object, got {type(data).__name__}")
        plugin = str(data.get("plugin") or data.get("type") or "").strip()
        if not plugin:
            raise ConfigError(f"targets[{index}] is missing 'plugin'")
        target_id = str(data.get("id") or plugin).strip()
        options = data.get("options") or {}
        if not isinstance(options, dict):
            raise ConfigError(f"targets[{index}].options must be an object")
        return cls(
            id=target_id,
            plugin=plugin,
            options=dict(options),
            tags=frozenset(data.get("tags") or ()),
        )

    def to_dict(self, *, redact_options: bool = True) -> dict:
        """Serialise for the run record.

        Options are elided by default: they hold endpoints and credentials, and a
        run artifact is frequently attached to a ticket.
        """
        out: dict[str, Any] = {"id": self.id, "plugin": self.plugin}
        if self.tags:
            out["tags"] = sorted(self.tags)
        if redact_options:
            out["options"] = sorted(self.options)  # key names only
        else:
            out["options"] = self.options
        return out


# --------------------------------------------------------------------------- #
# Run configuration
# --------------------------------------------------------------------------- #
@dataclass
class RunConfig:
    """Everything needed to plan and execute a run."""

    targets: list[TargetConfig] = field(default_factory=list)
    probes: list[str] = field(default_factory=list)
    detectors: list[str] = field(default_factory=list)
    transforms: list[str] = field(default_factory=lambda: ["identity"])
    orchestrator: str = "sweep"
    orchestrator_options: dict[str, Any] = field(default_factory=dict)
    detector_options: dict[str, dict[str, Any]] = field(default_factory=dict)
    probe_options: dict[str, dict[str, Any]] = field(default_factory=dict)

    seed: str = ""
    max_attempts: int = 0
    requests_per_minute: float = 60.0
    concurrency: int = 1
    timeout: float = 60.0

    include_tags: list[str] = field(default_factory=list)
    exclude_tags: list[str] = field(default_factory=list)
    min_risk: Risk | None = None
    fail_on: Risk | None = None

    include_payload_text: bool = True
    include_raw_responses: bool = False
    redact_artifacts: bool = True

    output_dir: str = "runs"
    formats: list[str] = field(default_factory=lambda: ["json", "markdown"])

    source_path: str = ""

    # -- construction ------------------------------------------------------ #
    def __post_init__(self) -> None:
        if not self.seed:
            self.seed = default_seed()
        self.concurrency = max(1, int(self.concurrency))
        if self.max_attempts < 0:
            raise ConfigError("max_attempts must be >= 0 (0 means 'authorization limit')")
        if not self.transforms:
            self.transforms = ["identity"]
        if "identity" not in self.transforms:
            # Always run the unmutated payload: without a baseline you cannot
            # tell whether a transform helped or the target was simply weak.
            self.transforms = ["identity", *self.transforms]

    @classmethod
    def from_dict(cls, data: dict, *, source_path: str = "") -> "RunConfig":
        if not isinstance(data, dict):
            raise ConfigError("config root must be an object")
        data = expand_env(data)
        unknown = set(data) - _KNOWN_KEYS
        if unknown:
            raise ConfigError(
                f"unknown config key(s): {', '.join(sorted(unknown))}. "
                f"Known keys: {', '.join(sorted(_KNOWN_KEYS))}"
            )

        raw_targets = data.get("targets") or []
        if not isinstance(raw_targets, list):
            raise ConfigError("'targets' must be a list")
        targets = [TargetConfig.from_dict(t, index=i) for i, t in enumerate(raw_targets)]
        seen: set[str] = set()
        for target in targets:
            if target.id in seen:
                raise ConfigError(f"duplicate target id {target.id!r}")
            seen.add(target.id)

        return cls(
            targets=targets,
            probes=_as_str_list(data.get("probes"), "probes"),
            detectors=_as_str_list(data.get("detectors"), "detectors"),
            transforms=_as_str_list(data.get("transforms"), "transforms") or ["identity"],
            orchestrator=str(data.get("orchestrator") or "sweep"),
            orchestrator_options=dict(data.get("orchestrator_options") or {}),
            detector_options={
                k: dict(v) for k, v in (data.get("detector_options") or {}).items()
            },
            probe_options={
                k: dict(v) for k, v in (data.get("probe_options") or {}).items()
            },
            seed=str(data.get("seed") or ""),
            max_attempts=int(data.get("max_attempts") or 0),
            # An explicit 0 means "no config-side limit"; the authorization
            # ceiling still applies. Absent means the conservative default.
            requests_per_minute=float(
                data["requests_per_minute"]
                if data.get("requests_per_minute") is not None
                else 60.0
            ),
            concurrency=int(data.get("concurrency") or 1),
            timeout=float(data.get("timeout") or 60.0),
            include_tags=_as_str_list(data.get("include_tags"), "include_tags"),
            exclude_tags=_as_str_list(data.get("exclude_tags"), "exclude_tags"),
            min_risk=Risk.parse(data["min_risk"]) if data.get("min_risk") else None,
            fail_on=Risk.parse(data["fail_on"]) if data.get("fail_on") else None,
            include_payload_text=bool(data.get("include_payload_text", True)),
            include_raw_responses=bool(data.get("include_raw_responses", False)),
            redact_artifacts=bool(data.get("redact_artifacts", True)),
            output_dir=str(data.get("output_dir") or "runs"),
            formats=_as_str_list(data.get("formats"), "formats") or ["json", "markdown"],
            source_path=source_path,
        )

    @classmethod
    def load(cls, path: str | Path) -> "RunConfig":
        """Load from ``.json`` or ``.toml`` (TOML needs Python 3.11+)."""
        file = Path(path)
        if not file.is_file():
            raise ConfigError(f"config file not found: {file}")
        text = file.read_text(encoding="utf-8")
        if file.suffix.lower() == ".toml":
            data = _load_toml(text, file)
        else:
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ConfigError(f"{file}: invalid JSON — {exc}") from None
        return cls.from_dict(data, source_path=str(file))

    # -- serialisation ----------------------------------------------------- #
    def to_dict(self, *, redact_options: bool = True) -> dict:
        return {
            "seed": self.seed,
            "orchestrator": self.orchestrator,
            "orchestrator_options": self.orchestrator_options,
            "targets": [t.to_dict(redact_options=redact_options) for t in self.targets],
            "probes": self.probes,
            "detectors": self.detectors,
            "transforms": self.transforms,
            "max_attempts": self.max_attempts,
            "requests_per_minute": self.requests_per_minute,
            "concurrency": self.concurrency,
            "timeout": self.timeout,
            "include_tags": self.include_tags,
            "exclude_tags": self.exclude_tags,
            "min_risk": self.min_risk.value if self.min_risk else None,
            "fail_on": self.fail_on.value if self.fail_on else None,
            "include_payload_text": self.include_payload_text,
            "redact_artifacts": self.redact_artifacts,
            "source_path": self.source_path,
        }


_KNOWN_KEYS = frozenset(
    {
        "targets",
        "probes",
        "detectors",
        "transforms",
        "orchestrator",
        "orchestrator_options",
        "detector_options",
        "probe_options",
        "seed",
        "max_attempts",
        "requests_per_minute",
        "concurrency",
        "timeout",
        "include_tags",
        "exclude_tags",
        "min_risk",
        "fail_on",
        "include_payload_text",
        "include_raw_responses",
        "redact_artifacts",
        "output_dir",
        "formats",
    }
)


def _as_str_list(value: Any, name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    raise ConfigError(f"'{name}' must be a string or list of strings")


def _load_toml(text: str, file: Path) -> dict:
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - depends on interpreter
        raise ConfigError(
            f"{file}: TOML configs need Python 3.11+ (tomllib). Use JSON instead."
        ) from None
    try:
        return tomllib.loads(text)
    except Exception as exc:  # tomllib.TOMLDecodeError
        raise ConfigError(f"{file}: invalid TOML — {exc}") from None
