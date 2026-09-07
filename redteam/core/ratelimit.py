"""Rate limiting, retry, and the attempt budget.

Three separate concerns, all of which exist for the same reason: an automated
red-team harness is, mechanically, a load generator pointed at someone's
production-shaped system. Left unbounded it becomes an availability incident,
which is both a bug and — under every rules-of-engagement document worth
signing — a breach of the engagement.

* :class:`RateLimiter` caps requests per minute, globally and per target.
* :func:`retry` handles transient transport failures with capped exponential
  backoff and jitter, and never retries a 4xx that means "you asked wrong".
* :class:`Budget` caps total attempts and is wired to the authorization record,
  so the ceiling is the one the operator was authorized for.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, TypeVar

from .errors import BudgetExceeded, TargetError

T = TypeVar("T")


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
class RateLimiter:
    """Thread-safe token bucket.

    ``requests_per_minute <= 0`` disables limiting, which is only appropriate
    for the offline ``mock`` target.
    """

    def __init__(
        self,
        requests_per_minute: float = 60.0,
        *,
        burst: int | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.rate = max(0.0, float(requests_per_minute)) / 60.0
        self.capacity = float(burst if burst is not None else max(1, int(requests_per_minute // 6) or 1))
        self._tokens = self.capacity
        self._updated = clock()
        self._lock = threading.Lock()
        self._sleep = sleep
        self._clock = clock

    @property
    def enabled(self) -> bool:
        return self.rate > 0

    def acquire(self, tokens: float = 1.0) -> float:
        """Block until ``tokens`` are available. Returns seconds waited."""
        if not self.enabled:
            return 0.0
        waited = 0.0
        while True:
            with self._lock:
                now = self._clock()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                deficit = tokens - self._tokens
                delay = deficit / self.rate
            self._sleep(delay)
            waited += delay


class NullRateLimiter(RateLimiter):
    """No-op limiter for offline targets and tests."""

    def __init__(self) -> None:
        super().__init__(requests_per_minute=0.0)

    def acquire(self, tokens: float = 1.0) -> float:
        return 0.0


# --------------------------------------------------------------------------- #
# Retry
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RetryPolicy:
    """Capped exponential backoff with full jitter."""

    attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    jitter: bool = True

    def delay_for(self, attempt: int, rand: float = 0.5) -> float:
        raw = min(self.max_delay, self.base_delay * (2 ** max(0, attempt - 1)))
        return raw * rand if self.jitter else raw


def retry(
    fn: Callable[[], T],
    policy: RetryPolicy = RetryPolicy(),
    *,
    retry_on: Callable[[Exception], bool] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    rand: Callable[[], float] | None = None,
) -> T:
    """Call ``fn``, retrying transient failures.

    ``retry_on`` decides retryability; the default retries :class:`TargetError`
    only when it is marked transient (see :func:`is_transient`). Non-transient
    errors propagate on the first failure — retrying a 400 just triples the load
    for the same answer.
    """
    import random as _random

    predicate = retry_on or is_transient
    randfn = rand or _random.random
    last: Exception | None = None
    for attempt in range(1, max(1, policy.attempts) + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - re-raised below
            last = exc
            if attempt >= policy.attempts or not predicate(exc):
                raise
            sleep(policy.delay_for(attempt, randfn()))
    assert last is not None  # pragma: no cover - loop always raises or returns
    raise last


#: HTTP statuses worth retrying: rate limiting and server-side faults.
TRANSIENT_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})


def is_transient(exc: Exception) -> bool:
    status = getattr(exc, "status", None)
    if isinstance(status, int):
        return status in TRANSIENT_STATUSES
    if isinstance(exc, TargetError):
        return bool(getattr(exc, "transient", False))
    return isinstance(exc, (TimeoutError, ConnectionError))


# --------------------------------------------------------------------------- #
# Budget
# --------------------------------------------------------------------------- #
@dataclass
class Budget:
    """Total-attempt ceiling for a run.

    ``limit <= 0`` means unlimited, which the authorization loader refuses to
    produce: an authorization record must state a maximum.
    """

    limit: int = 0
    spent: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def unlimited(self) -> bool:
        return self.limit <= 0

    @property
    def remaining(self) -> int:
        if self.unlimited:
            return 2**31
        return max(0, self.limit - self.spent)

    def exhausted(self) -> bool:
        return not self.unlimited and self.spent >= self.limit

    def take(self, n: int = 1) -> None:
        """Consume ``n`` attempts, raising :class:`BudgetExceeded` if over."""
        with self._lock:
            if not self.unlimited and self.spent + n > self.limit:
                raise BudgetExceeded(
                    f"attempt budget exhausted ({self.spent}/{self.limit}); "
                    f"raise scope.max_attempts in the authorization record if the "
                    f"engagement allows it"
                )
            self.spent += n

    def try_take(self, n: int = 1) -> bool:
        """Consume ``n`` attempts if available; return whether it succeeded."""
        try:
            self.take(n)
            return True
        except BudgetExceeded:
            return False
