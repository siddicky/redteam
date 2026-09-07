"""Subprocess target: for an agent or CLI that runs locally.

Plenty of the systems worth red-teaming are not HTTP services — they are the
coding agent, the shell assistant, or the batch summariser someone wired up with
a `main()` and a model client. This adapter drives one as a child process.

The command is executed with ``shell=False`` and an explicit argv list. That is
not a convenience choice: building a shell string from probe text would let a
payload escape the framework and run as a command on the operator's machine,
which would turn this tool into the vulnerability.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Sequence

from ..core.errors import ConfigError, TargetError
from ..core.result import Message, TargetResponse, ToolCall
from .base import TARGETS, Target

#: Environment variables passed through to the child unless ``env_passthrough``
#: says otherwise. A minimal set keeps a probe from reading the operator's whole
#: environment out of the subprocess.
DEFAULT_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR")


@TARGETS.register(
    "exec.command",
    summary="Local CLI or agent driven as a subprocess (shell=False)",
    tags={"local", "live"},
)
class CommandTarget(Target):
    """Run a local command once per attempt.

    Options:

    ``command``
        argv list, e.g. ``["python", "-m", "myagent", "--json"]``. Required.
    ``input_mode``
        ``stdin`` (default) or ``argv`` — appended as a final argument.
    ``input_format``
        ``text`` (default: the rendered conversation) or ``json`` (a
        ``{"messages": [...]}`` document, for agents that want structure).
    ``output_format``
        ``text`` (default) or ``json``, in which case ``response_path`` and
        ``tool_calls_path`` are read from the parsed stdout.
    ``cwd``, ``env``, ``env_passthrough``, ``timeout``.
    """

    def __init__(
        self,
        *,
        command: Sequence[str] | None = None,
        input_mode: str = "stdin",
        input_format: str = "text",
        output_format: str = "text",
        response_path: str = "output",
        tool_calls_path: str = "",
        cwd: str = "",
        env: dict[str, str] | None = None,
        env_passthrough: Sequence[str] = DEFAULT_ENV_KEYS,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        if not command or isinstance(command, str) or not all(
            isinstance(part, str) for part in command
        ):
            raise ConfigError(
                f"target {self.id!r} requires 'command' as a list of strings, e.g. "
                f'["python", "-m", "myagent"] — a single string is refused because '
                f"it would need a shell"
            )
        if input_mode not in ("stdin", "argv"):
            raise ConfigError(f"input_mode must be 'stdin' or 'argv', got {input_mode!r}")
        if input_format not in ("text", "json"):
            raise ConfigError(f"input_format must be 'text' or 'json', got {input_format!r}")
        if output_format not in ("text", "json"):
            raise ConfigError(f"output_format must be 'text' or 'json', got {output_format!r}")
        self.command = list(command)
        self.input_mode = input_mode
        self.input_format = input_format
        self.output_format = output_format
        self.response_path = response_path
        self.tool_calls_path = tool_calls_path
        self.cwd = cwd or None
        self.env_overrides = dict(env or {})
        self.env_passthrough = tuple(env_passthrough)

    @property
    def endpoint(self) -> str:
        return f"exec:{self.command[0]}"

    @property
    def supports_tools(self) -> bool:
        return bool(self.tool_calls_path)

    def describe(self) -> dict[str, Any]:
        out = super().describe()
        out["command"] = self.command
        out["cwd"] = self.cwd or os.getcwd()
        return out

    def _child_env(self) -> dict[str, str]:
        env = {k: os.environ[k] for k in self.env_passthrough if k in os.environ}
        env.update(self.env_overrides)
        return env

    def _render_input(self, messages: Sequence[Message]) -> str:
        if self.input_format == "json":
            return json.dumps(
                {"messages": [m.to_dict() for m in messages]}, ensure_ascii=False
            )
        return "\n\n".join(f"{m.role.upper()}: {m.content}" for m in messages)

    def _send(
        self, messages: Sequence[Message], tools: Sequence[dict[str, Any]]
    ) -> TargetResponse:
        rendered = self._render_input(messages)
        argv = list(self.command)
        stdin_data: str | None = None
        if self.input_mode == "argv":
            argv.append(rendered)
        else:
            stdin_data = rendered

        try:
            completed = subprocess.run(  # noqa: S603 - argv list, shell=False
                argv,
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.cwd,
                env=self._child_env(),
                shell=False,
                check=False,
            )
        except FileNotFoundError:
            raise TargetError(f"command not found: {argv[0]!r}") from None
        except subprocess.TimeoutExpired:
            error = TargetError(f"{argv[0]!r} timed out after {self.timeout}s")
            error.transient = True  # type: ignore[attr-defined]
            raise error from None

        stdout = completed.stdout or ""
        if completed.returncode != 0 and not stdout.strip():
            stderr = (completed.stderr or "").strip()[:400]
            raise TargetError(
                f"{argv[0]!r} exited {completed.returncode} with no stdout: {stderr}"
            )

        if self.output_format == "json":
            return self._parse_json_output(stdout, completed.returncode)
        return TargetResponse(
            text=stdout,
            finish_reason=f"exit:{completed.returncode}",
            raw={"returncode": completed.returncode, "stderr": (completed.stderr or "")[:2000]},
        )

    def _parse_json_output(self, stdout: str, returncode: int) -> TargetResponse:
        from .http import _dig, _parse_arguments  # local import avoids a cycle

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            raise TargetError(
                f"expected JSON on stdout, got: {stdout[:200]!r}"
            ) from None
        text = _dig(data, self.response_path)
        if text is None:
            raise TargetError(
                f"response_path {self.response_path!r} not present in stdout JSON"
            )
        calls: list[ToolCall] = []
        if self.tool_calls_path:
            for entry in _dig(data, self.tool_calls_path) or []:
                if isinstance(entry, dict):
                    calls.append(
                        ToolCall(
                            name=str(entry.get("name", "")),
                            arguments=_parse_arguments(entry.get("arguments")),
                            call_id=str(entry.get("id", "")),
                        )
                    )
        return TargetResponse(
            text=text if isinstance(text, str) else json.dumps(text),
            tool_calls=tuple(calls),
            finish_reason=f"exit:{returncode}",
            raw=data if isinstance(data, dict) else {"output": data},
        )
