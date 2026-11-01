"""Secret redaction for logs, errors and audit payloads."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

REDACTED = "[redacted]"
_SENSITIVE_KEY = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|credential|signature|csrf)",
    re.IGNORECASE,
)
_PATTERNS = [
    re.compile(r"axk_[a-z0-9]+_[A-Za-z0-9_-]{16,}"),  # Axentra API keys
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),  # JWTs
    re.compile(r"(?i)(postgres(ql)?://[^:/@\s]+:)[^@\s]+@"),
]


def redact_text(text: str) -> str:
    for pattern in _PATTERNS:
        if pattern.pattern.startswith("(?i)(postgres"):
            text = pattern.sub(lambda m: m.group(1) + REDACTED + "@", text)
        else:
            text = pattern.sub(REDACTED, text)
    return text


def redact(value: Any, _depth: int = 0) -> Any:
    """Return a copy with sensitive keys and token-like strings replaced."""
    if _depth > 8:
        return REDACTED
    if isinstance(value, Mapping):
        return {
            k: (REDACTED if isinstance(k, str) and _SENSITIVE_KEY.search(k) else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth + 1) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
