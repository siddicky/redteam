"""Low-level encodings shared by transforms and the offline simulator.

Encoding attacks work because of a split between two readers of the same string:
a guardrail that pattern-matches the surface form, and a model that understands
the decoded form. To model that honestly, the simulator has to be able to decode
what the transforms encode — so both sides import from here rather than
duplicating (and drifting on) the same table.

Everything is pure text manipulation over the standard library. Nothing here is
an exploit; these are the same codecs a log viewer uses.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata

# --------------------------------------------------------------------------- #
# Base64 / hex
# --------------------------------------------------------------------------- #
def b64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def b64_decode_candidates(text: str) -> list[str]:
    """Every base64-looking blob in ``text``, decoded when it yields valid UTF-8.

    Used by the simulator to see what a model would "read through" an encoding.
    Blobs that do not decode to text are skipped rather than raising: most
    base64-shaped noise in real traffic is not base64.
    """
    out: list[str] = []
    for match in _B64_BLOB_RE.finditer(text):
        blob = match.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(padded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded.isprintable() or "\n" in decoded:
            out.append(decoded)
    return out


def hex_encode(text: str) -> str:
    return text.encode("utf-8").hex()


_HEX_BLOB_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){12,}\b")


def hex_decode_candidates(text: str) -> list[str]:
    out: list[str] = []
    for match in _HEX_BLOB_RE.finditer(text):
        blob = match.group(0)
        if len(blob) % 2:
            continue
        try:
            decoded = bytes.fromhex(blob).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        out.append(decoded)
    return out


# --------------------------------------------------------------------------- #
# ROT13
# --------------------------------------------------------------------------- #
def rot13(text: str) -> str:
    """Its own inverse, which is why it appears on both sides of the pipeline."""
    return codecs.encode(text, "rot_13")


# --------------------------------------------------------------------------- #
# Leetspeak
# --------------------------------------------------------------------------- #
LEET_MAP = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1"}
_LEET_REVERSE = {v: k for k, v in reversed(list(LEET_MAP.items()))}


def leet_encode(text: str) -> str:
    return "".join(LEET_MAP.get(ch.lower(), ch) for ch in text)


def leet_decode(text: str) -> str:
    """Best-effort inverse. Lossy — ``1`` maps back to ``i``, not ``l``."""
    return "".join(_LEET_REVERSE.get(ch, ch) for ch in text)


# --------------------------------------------------------------------------- #
# Invisible and confusable characters
# --------------------------------------------------------------------------- #
#: Zero-width joiner/non-joiner and the zero-width space.
ZERO_WIDTH = ("​", "‌", "‍", "﻿")

#: Cyrillic and Greek letters that render like Latin ones. These defeat exact
#: string matching in a filter while a model still reads the intended word.
HOMOGLYPHS = {
    "a": "а",  # CYRILLIC SMALL LETTER A
    "c": "с",
    "e": "е",
    "i": "і",
    "j": "ј",
    "o": "о",
    "p": "р",
    "s": "ѕ",
    "x": "х",
    "y": "у",
}
_HOMOGLYPH_REVERSE = {v: k for k, v in HOMOGLYPHS.items()}


def zero_width_inject(text: str, every: int = 1, char: str = "​") -> str:
    """Insert a zero-width character between characters of ``text``."""
    if every <= 0:
        return text
    out: list[str] = []
    for index, ch in enumerate(text):
        out.append(ch)
        if ch.strip() and (index + 1) % every == 0:
            out.append(char)
    return "".join(out)


def strip_invisible(text: str) -> str:
    """Remove zero-width and other format characters.

    This is the normalisation a defender should apply *before* filtering; the
    simulator applies it to model input to reproduce why a filter that skips it
    gets bypassed.
    """
    return "".join(
        ch for ch in text if ch not in ZERO_WIDTH and unicodedata.category(ch) != "Cf"
    )


def homoglyph_encode(text: str, ratio: int = 1) -> str:
    """Swap Latin letters for confusable Cyrillic/Greek lookalikes."""
    out: list[str] = []
    seen = 0
    for ch in text:
        replacement = HOMOGLYPHS.get(ch.lower())
        if replacement and (ratio <= 1 or seen % ratio == 0):
            out.append(replacement if ch.islower() else replacement.upper())
        else:
            out.append(ch)
        if replacement:
            seen += 1
    return "".join(out)


def fold_confusables(text: str) -> str:
    """Map confusables back to ASCII and strip accents.

    Together with :func:`strip_invisible` this is the canonical form the
    simulator's "model" reads.
    """
    folded = "".join(_HOMOGLYPH_REVERSE.get(ch, ch) for ch in text)
    decomposed = unicodedata.normalize("NFKD", folded)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


# --------------------------------------------------------------------------- #
# Canonicalisation
# --------------------------------------------------------------------------- #
def canonical_forms(text: str) -> list[str]:
    """Every reading of ``text`` a capable model might arrive at.

    Returns the normalised surface form first, then any decoded payloads found
    inside it. Detectors and the simulator both use this so that "the model
    understood the obfuscated instruction" is modelled rather than assumed.
    """
    normalised = fold_confusables(strip_invisible(text))
    forms = [normalised]
    for decoded in b64_decode_candidates(normalised) + hex_decode_candidates(normalised):
        forms.append(decoded)
    rotated = rot13(normalised)
    forms.append(rotated)
    reversed_text = normalised[::-1]
    forms.append(reversed_text)
    forms.append(leet_decode(normalised))
    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for form in forms:
        if form not in seen:
            seen.add(form)
            unique.append(form)
    return unique
