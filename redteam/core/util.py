"""Small shared helpers: identifiers, timestamps, deterministic randomness.

Determinism is a hard requirement, not a nicety. A red-team run that cannot be
reproduced cannot be handed to the team that has to fix the finding, and it
cannot be used as a regression test once they have. Everything random in the
framework draws from :func:`rng_for`, seeded from the run seed, so re-running
with the same seed and the same probe set reproduces the same plan.
"""

from __future__ import annotations

import hashlib
import os
import random
import re
from datetime import datetime, timezone


def now_iso() -> str:
    """UTC timestamp, second precision, suffixed ``Z``."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def new_run_id(seed: str = "") -> str:
    """A run id of the form ``20260730T101500Z-ab12cd``.

    The suffix comes from the seed when one is given so that a seeded run has a
    stable, meaningful id; otherwise it is random.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if seed:
        suffix = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:6]
    else:
        suffix = os.urandom(3).hex()
    return f"{stamp}-{suffix}"


def attempt_id(*parts: str) -> str:
    """Short, stable id derived from an attempt's coordinates."""
    blob = "|".join(parts)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]


def default_seed() -> str:
    """A fresh random seed, as a hex string."""
    return os.urandom(8).hex()


def rng_for(seed: str, *namespace: str) -> random.Random:
    """A :class:`random.Random` deterministically derived from seed+namespace."""
    key = "|".join((seed, *namespace))
    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str, max_length: int = 48) -> str:
    """Lowercase, hyphenated slug — used for payload ids and filenames."""
    slug = _SLUG_RE.sub("-", value.strip().lower()).strip("-")
    return slug[:max_length].strip("-") or "item"


def truncate(text: str, limit: int) -> str:
    """Truncate with an explicit marker, so a report never implies it showed
    everything when it did not."""
    if limit <= 0 or len(text) <= limit:
        return text
    return text[:limit] + f"…[truncated {len(text) - limit} chars]"


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))
