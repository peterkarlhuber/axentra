"""Secret redaction for logs, errors and audit payloads.

URLs reach logs and stored values in more than one spelling: ``?token=abc`` in a request line,
``%3Ftoken%3Dabc`` when the URL is itself a query value (``return_to=...``), and ``%253F...`` one
level deeper. Every pattern here therefore matches the separators, ``=`` and the ``_`` of a token
prefix both literally and percent-encoded (any number of times, either hex case).
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any
from urllib.parse import unquote

REDACTED = "[redacted]"
_SENSITIVE_KEY = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|credential|signature|csrf)",
    re.IGNORECASE,
)


def _enc(ch: str) -> str:
    """``ch`` literally or percent-encoded, also repeatedly (``%5F``, ``%255F``; hex in either case)."""
    codes = sorted({f"{ord(c):02X}" for c in {ch, ch.lower(), ch.upper()}})
    return f"(?:{re.escape(ch)}|%(?:25)*(?:{'|'.join(codes)}))"


def _word(word: str) -> str:
    return "".join(_enc(ch) for ch in word)


_SEP = f"(?:{_enc('?')}|{_enc('&')})"
_EQ = _enc("=")
#: A value up to the next literal ``&``, white space or quote. For an encoded parameter
#: (``%26`` is no stop) this redacts more than the value, never less.
_VALUE = r"[^&\s\"']*"
#: Parameter names whose values are login secrets: ``*token`` (``token``, ``id_token``,
#: ``setup_token`` ...), ``invitation`` and ``setup``.
_SECRET_QUERY_NAME = f"(?:[a-z0-9]|{_enc('_')})*{_word('token')}|{_word('invitation')}|{_word('setup')}"
_SECRET_QUERY = re.compile(f"(?i)({_SEP}(?:{_SECRET_QUERY_NAME}){_EQ}){_VALUE}")
# Adapted from peterkarlhuber/nodestro-api src/nodestro_api/identity.py at e7fb1dba1f5521d13ab2d90ac41e101f2c6f5bea (MIT, Copyright (c) 2026 Peter Karlhuber)
#: As above plus OIDC ``code`` and ``state`` (request lines of the OIDC callback).
_AUTH_QUERY = re.compile(
    f"(?i)({_SEP}(?:{_SECRET_QUERY_NAME}|{_word('code')}|{_word('state')}){_EQ}){_VALUE}"
)
_URLSAFE_CHAR = r"(?:[A-Za-z0-9_-]|%(?:25)*[0-9A-Fa-f]{2})"
_PATTERNS = [
    re.compile(f"axk{_enc('_')}[a-z0-9]+{_enc('_')}{_URLSAFE_CHAR}{{16,}}"),  # Axentra API keys
    # Axentra one-time tokens: tenant invitations (``axinv_``), product invitations (``axpinv_``), password resets
    # (``axpwr_``), email verifications (``axemv_``) and setup tokens (``axsetup_``).
    re.compile(f"ax(?:inv|pinv|pwr|emv|setup){_enc('_')}{_URLSAFE_CHAR}{{16,}}"),
    re.compile(f"whsec{_enc('_')}{_URLSAFE_CHAR}{{16,}}"),  # Axentra webhook signing secrets
    # Signed download tokens ``d1.<kid>.<payload>.<mac>`` (storage/tokens.py), such as the last segment of
    # ``/v1/files/download/<token>`` in a request line.
    re.compile(
        f"(?:(?<![A-Za-z0-9_-])|(?<=%[0-9A-Fa-f]{{2}}))d1{_enc('.')}[A-Za-z0-9]+{_enc('.')}{_URLSAFE_CHAR}{{8,}}{_enc('.')}{_URLSAFE_CHAR}{{16,}}"
    ),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),  # JWTs
]
_DSN = re.compile(r"(?i)(postgres(ql)?://[^:/@\s]+:)[^@\s]+@")
#: Values kept after a visible prefix (group 1), MUP-ONA VB-4:
_PREFIXED = [
    # ``Authorization: Basic <base64>`` (also ``Proxy-Authorization`` and a header dict ``'Authorization': 'Basic ...'``).
    re.compile(r"(?i)(authorization[\"']?\s*[:=]\s*[\"']?basic\s+)[A-Za-z0-9+/=._~-]+"),
    # A cookie header carries session cookies: everything after ``Cookie:`` / ``Set-Cookie:`` up to the line end.
    re.compile(r"(?i)((?<![a-z0-9_-])(?:set-)?cookie\s*:\s*)[^\r\n]+"),
    # Axentra's session and login cookies wherever they appear (``name=value``).
    re.compile(r"(?i)((?:__Host-)?axentra-(?:session|login)=)[^;,\s\"']+"),
    # ``password=...``, ``new_password=...``, ``passwd=...`` and ``client_secret=...`` (form bodies, query strings,
    # command lines; ``=`` and ``_`` also percent-encoded).
    re.compile(f"(?i)((?:pass(?:wor)?d|client{_enc('_')}secret){_EQ})[^&\\s\"']+"),
    # The same names as a quoted key with a quoted value (JSON or a Python dict in free text, such as a request body
    # in an error message: ``{"password": "..."}``, ``'client_secret': '...'``), MUP-ONA VB-7.
    # The value ends at its closing quote (escaped quotes included).
    re.compile(
        r"""(?i)((["'])[a-z0-9_-]*(?:pass(?:wor)?d|client[_-]secret)\2\s*:\s*(["']))(?:\\.|(?!\3)[^\\\r\n])+"""
    ),
]


def redact_text(text: str) -> str:
    for pattern in _PATTERNS:
        text = pattern.sub(REDACTED, text)
    text = _DSN.sub(lambda m: m.group(1) + REDACTED + "@", text)
    for prefixed in _PREFIXED:
        text = prefixed.sub(lambda m: m.group(1) + REDACTED, text)
    if "=" in text or "%" in text:
        text = _SECRET_QUERY.sub(lambda m: m.group(1) + REDACTED, text)
    return text


def redact_auth_query(text: str) -> str:
    """Login secrets in a request line: the values of ``code``, ``state``, ``*token``, ``setup`` and
    ``invitation`` query parameters, literal or percent-encoded inside another parameter (such as
    ``return_to=%2Fx%3Ftoken%3D...``), and everything :func:`redact_text` removes."""
    if "=" in text or "%" in text:
        text = _AUTH_QUERY.sub(lambda m: m.group(1) + REDACTED, text)
    return redact_text(text)


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


# -- URLs that are stored: no secret may survive in them ------------------------------------------

#: Query parameter names that never belong in a stored URL (matched on the decoded, lowercased name).
_SECRET_PARAM = re.compile(r"token|invitation|setup|" + _SENSITIVE_KEY.pattern, re.IGNORECASE)


def fully_unquote(value: str, *, limit: int = 8) -> str:
    """Percent-decode until nothing changes (``%253F`` -> ``%3F`` -> ``?``), at most ``limit`` rounds."""
    for _ in range(limit):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def _query_of(text: str) -> str:
    return text.split("#", 1)[0].split("?", 1)[-1]


def carries_secret(value: str, _depth: int = 0) -> bool:
    """Whether ``value`` (a URL, a path, a query or a query value, in any encoding) holds a secret:
    a token-like string, or a query parameter named like a secret, also nested in another value."""
    decoded = fully_unquote(value)
    if redact_text(decoded) != decoded:
        return True
    if _depth >= 4 or "=" not in decoded:
        return False
    for piece in re.split(r"[&;]", _query_of(decoded)):
        name, _, inner = piece.partition("=")
        if _SECRET_PARAM.search(name.strip()) or carries_secret(inner, _depth + 1):
            return True
    return False


def strip_secret_params(url: str) -> tuple[str, list[tuple[str, str]]]:
    """``url`` (a path or an absolute URL) without the query parameters that carry a secret.

    A parameter is removed when its decoded name looks like a secret (``token``, ``*_token``,
    ``invitation``, ``setup``, ``password``, ...) or its value holds one in any encoding (a token,
    or a nested URL with such a parameter, as in ``return_to=%2Fx%3Ftoken%3D...``). Other
    parameters keep their exact spelling. A fragment that carries a secret is dropped; a path that
    does (``/a%3Ftoken%3D...``) makes the whole URL its origin's ``/``. Returns the cleaned URL and
    the removed ``(decoded name, decoded value)`` pairs, in order.
    """
    removed: list[tuple[str, str]] = []
    rest, hash_mark, fragment = url.partition("#")
    head, question, query = rest.partition("?")
    scheme_end = head.find("://")
    path_at = head.find("/", scheme_end + 3) if scheme_end != -1 else 0
    origin, path = (head[:path_at], head[path_at:]) if path_at != -1 else (head, "")
    if carries_secret(path):
        return (origin + "/") if origin else "/", [("#path", "")]
    kept: list[str] = []
    for piece in query.split("&") if question else []:
        raw_name, has_value, raw_value = piece.partition("=")
        name = fully_unquote(raw_name.replace("+", " "))
        if _SECRET_PARAM.search(name) or carries_secret(raw_value if has_value else raw_name):
            removed.append((name, fully_unquote(raw_value.replace("+", " "))))
        else:
            kept.append(piece)
    out = head + ("?" + "&".join(kept) if kept else "")
    if hash_mark and fragment:
        if carries_secret(fragment):
            removed.append(("#", ""))
        else:
            out += "#" + fragment
    return out, removed
