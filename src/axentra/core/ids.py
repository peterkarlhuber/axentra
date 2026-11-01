"""Opaque, prefixed identifiers and random tokens.

Ids look like ``ten_01jbx3k7d2h9q8w5v4c3b2a1z0``: a type prefix plus a 26 character lowercase
Crockford base32 body (48 bit millisecond timestamp + 80 random bits, ULID layout). They sort
roughly by creation time, which keeps B-tree indexes compact and makes cursors stable.
"""

from __future__ import annotations

import re
import secrets
import time

_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"
_ID_RE = re.compile(r"^[a-z]{2,4}_[0-9a-hjkmnp-tv-z]{26}$")


def _b32(value: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(_ALPHABET[value & 31])
        value >>= 5
    return "".join(reversed(out))


def new_id(prefix: str) -> str:
    if not re.fullmatch(r"[a-z]{2,4}", prefix):
        raise ValueError(f"invalid id prefix: {prefix!r}")
    millis = int(time.time() * 1000) & ((1 << 48) - 1)
    rand = secrets.randbits(80)
    return f"{prefix}_{_b32((millis << 80) | rand, 26)}"


def is_id(value: str, prefix: str | None = None) -> bool:
    if not _ID_RE.match(value):
        return False
    return prefix is None or value.startswith(prefix + "_")


def new_token(nbytes: int = 32) -> str:
    """A URL-safe random secret (256 bits by default)."""
    return secrets.token_urlsafe(nbytes)
