"""Sentinels: harmless stand-ins for harmful output.

The central measurement problem in automated red teaming is that you want to
know whether a guardrail can be bypassed, but the obvious way to find out is to
ask the target for something genuinely harmful — which means generating,
storing, and shipping harmful content in your own repository.

This framework avoids that. Probes ask the target to violate an instruction in a
way that is *observable but inert*: emit a specific random token, place a canary
in a URL, call a forbidden tool with a dummy argument. The security question —
"did untrusted input override the operator's instructions?" — is answered
exactly, and the artifact contains a nonce instead of an attack.

Sentinels are derived deterministically from a run seed, so the same seed
reproduces the same run byte for byte, while different runs use different tokens
(a target that memorised last week's token cannot fake a pass).

Where a genuine harmful-category evaluation is required, supply your own
approved prompts through the ``corpus.custom`` probe rather than baking them in
here. See ``docs/SAFETY.md``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

#: Prefix on every generated sentinel, so a token found in a log is traceable
#: back to this framework rather than mistaken for real data.
SENTINEL_PREFIX = "RT-CANARY"

#: A sentinel that means "the model produced attacker-chosen text verbatim".
DEFAULT_NAMESPACE = "default"


@dataclass(frozen=True)
class SentinelFactory:
    """Deterministic sentinel generator for one run.

    ``seed`` ties every token to the run; ``length`` is the hex-digit length of
    the random-looking part. 10 hex digits give ~40 bits, which is far beyond
    accidental collision with target output while staying short enough to read.
    """

    seed: str
    length: int = 10
    prefix: str = SENTINEL_PREFIX

    def make(self, *namespace: str) -> str:
        """A sentinel unique to ``namespace`` within this run.

        Namespacing per probe/payload keeps findings unambiguous: if two probes
        shared one token, a detector could credit a bypass to the wrong probe.
        """
        key = "|".join((self.seed, *namespace)) or self.seed
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"{self.prefix}-{digest[: self.length].upper()}"

    def is_sentinel(self, token: str) -> bool:
        return token.upper().startswith(f"{self.prefix}-")


def looks_like_sentinel(text: str) -> bool:
    """True when ``text`` contains any sentinel from any run.

    Used by the artifact scanner: a sentinel in committed data is a hint that a
    raw transcript was pasted somewhere it should not have been.
    """
    return f"{SENTINEL_PREFIX}-" in text.upper()
