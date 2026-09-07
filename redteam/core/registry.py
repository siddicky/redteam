"""A tiny plugin registry.

Every extension point in the framework — targets, probes, detectors,
transforms, orchestrators, reporters — is a :class:`Registry`. Components
register themselves by a stable dotted id (``indirect.document``,
``refusal.heuristic``) and are resolved by that id from config or the CLI.

The registry deliberately stores *factories* rather than instances so a
component can be constructed with per-run options::

    @PROBES.register("direct.instruction_override")
    class InstructionOverride(Probe): ...

    probe = PROBES.create("direct.instruction_override", strength=3)

Ids are validated on registration so a typo fails at import time rather than
silently producing an unreachable plugin.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Generic, Iterator, TypeVar

from .errors import RegistryError

T = TypeVar("T")

_ID_RE = re.compile(r"\A[a-z0-9]+(?:[._][a-z0-9]+)*\Z")


@dataclass(frozen=True)
class Entry(Generic[T]):
    """One registered component."""

    id: str
    factory: Callable[..., T]
    summary: str
    tags: frozenset[str]

    @property
    def family(self) -> str:
        """The id's first dotted segment (``indirect`` for ``indirect.document``)."""
        return self.id.split(".", 1)[0]


class Registry(Generic[T]):
    """Name → factory mapping for one extension point."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self._entries: dict[str, Entry[T]] = {}

    # -- registration ------------------------------------------------------ #
    def register(
        self,
        id: str,
        *,
        summary: str = "",
        tags: frozenset[str] | set[str] | tuple[str, ...] = (),
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """Decorator registering a factory (usually a class) under ``id``."""
        if not _ID_RE.match(id):
            raise RegistryError(
                f"invalid {self.kind} id {id!r}: use lowercase dotted segments, "
                f"e.g. 'indirect.document'"
            )
        if id in self._entries:
            raise RegistryError(f"duplicate {self.kind} id: {id!r}")

        def decorate(factory: Callable[..., T]) -> Callable[..., T]:
            doc = (summary or (factory.__doc__ or "")).strip()
            first_line = doc.splitlines()[0].strip() if doc else ""
            self._entries[id] = Entry(
                id=id,
                factory=factory,
                summary=first_line,
                tags=frozenset(tags),
            )
            # Let a component discover its own registered id.
            try:
                setattr(factory, "id", id)
            except (AttributeError, TypeError):  # pragma: no cover - builtins
                pass
            return factory

        return decorate

    # -- lookup ------------------------------------------------------------ #
    def __contains__(self, id: object) -> bool:
        return id in self._entries

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[Entry[T]]:
        for id in sorted(self._entries):
            yield self._entries[id]

    def entry(self, id: str) -> Entry[T]:
        try:
            return self._entries[id]
        except KeyError:
            raise RegistryError(
                f"unknown {self.kind}: {id!r}. Available: {', '.join(self.names())}"
            ) from None

    def names(self) -> list[str]:
        return sorted(self._entries)

    def create(self, id: str, **options) -> T:
        """Instantiate the component registered under ``id``."""
        return self.entry(id).factory(**options)

    def resolve(self, patterns: list[str] | tuple[str, ...] | None) -> list[str]:
        """Expand id selectors into concrete ids.

        Accepts exact ids, a family prefix (``indirect`` selects every
        ``indirect.*``), and ``*`` globs (``*.document``). ``None`` or an empty
        selector list means "everything". Order is stable (sorted) and
        duplicates collapse, so a plan is reproducible.
        """
        if not patterns:
            return self.names()
        from fnmatch import fnmatch

        selected: set[str] = set()
        for pattern in patterns:
            pattern = pattern.strip()
            if not pattern:
                continue
            if pattern in self._entries:
                selected.add(pattern)
                continue
            hits = {
                e.id
                for e in self
                if fnmatch(e.id, pattern) or e.family == pattern
            }
            if not hits:
                raise RegistryError(
                    f"{self.kind} selector {pattern!r} matched nothing. "
                    f"Available: {', '.join(self.names())}"
                )
            selected |= hits
        return sorted(selected)

    def with_tag(self, tag: str) -> list[str]:
        return sorted(e.id for e in self if tag in e.tags)
