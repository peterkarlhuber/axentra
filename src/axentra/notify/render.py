"""A deliberately tiny, safe template language: ``{{ name }}`` placeholders and nothing else.

- No expressions, filters, loops, attribute access or code execution: a placeholder is a variable
  name (``[A-Za-z_][A-Za-z0-9_]{0,63}``) between ``{{`` and ``}}`` with optional spaces.
- Any other ``{{`` is a template error (found when the template is saved, never at send time).
- Substitution is a single pass, so a value containing ``{{ x }}`` is never expanded again.
- In HTML bodies every value is HTML-escaped (``&<>"'``); text bodies and subjects are not.
- A placeholder without a value (missing or ``None``) is a validation error listing the names.
- Rendered subjects never contain line breaks (header injection).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import html
import re
from typing import Any, Literal

from axentra.core.errors import ValidationFailed

_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]{0,63})\s*\}\}")
_OPEN = "{{"
MAX_VARIABLES = 50
MAX_VALUE_CHARS = 10_000

Mode = Literal["text", "html", "subject"]


def placeholders(source: str) -> list[str]:
    """Names used by ``source``; raises :class:`ValidationFailed` on malformed ``{{``."""
    names: list[str] = []
    pos = 0
    for m in _PLACEHOLDER.finditer(source):
        if _OPEN in source[pos : m.start()]:
            raise ValidationFailed("invalid placeholder syntax; use {{ name }}")
        if m.group(1) not in names:
            names.append(m.group(1))
        pos = m.end()
    if _OPEN in source[pos:]:
        raise ValidationFailed("invalid placeholder syntax; use {{ name }}")
    return names


def _stringify(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    raise ValidationFailed("template variables must be strings, numbers or booleans")


def check_variables(variables: Mapping[str, Any]) -> dict[str, Any]:
    if len(variables) > MAX_VARIABLES:
        raise ValidationFailed(f"at most {MAX_VARIABLES} variables are allowed")
    out: dict[str, Any] = {}
    for k, v in variables.items():
        if not isinstance(k, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", k):
            raise ValidationFailed("variable names must be identifiers (letters, digits, underscore)")
        if v is not None and len(_stringify(v)) > MAX_VALUE_CHARS:
            raise ValidationFailed(f"variable {k} is too long")
        out[k] = v
    return out


def render(source: str, variables: Mapping[str, Any], mode: Mode) -> str:
    names = placeholders(source)
    missing = [n for n in names if variables.get(n) is None]
    if missing:
        raise ValidationFailed(
            "missing template variables: " + ", ".join(missing), extra={"missing": missing}
        )

    def sub(m: re.Match[str]) -> str:
        value = _stringify(variables[m.group(1)])
        if mode == "html":
            return html.escape(value, quote=True)
        if mode == "subject":
            return " ".join(value.splitlines())
        return value

    out = _PLACEHOLDER.sub(sub, source)
    if mode == "subject":
        out = " ".join(out.splitlines()).strip()
    return out


@dataclass(frozen=True, slots=True)
class Rendered:
    locale: str
    subject: str
    text: str
    html: str | None


def resolve_locale(requested: str | None, available: list[str] | set[str] | Mapping[str, Any]) -> str:
    """Fallback chain: ``de-AT`` -> ``de`` -> ``en``; raises if even ``en`` is missing."""
    chain: list[str] = []
    if requested:
        req = requested.strip().replace("_", "-").lower()
        if req:
            chain.append(req)
            base = req.split("-")[0]
            if base != req:
                chain.append(base)
    chain.append("en")
    lowered = {k.lower(): k for k in available}
    for loc in chain:
        if loc in lowered:
            return lowered[loc]
    raise ValidationFailed("the template has no variant for this locale and no 'en' fallback")


def render_variant(
    variants: Mapping[str, Mapping[str, Any]], locale: str | None, variables: Mapping[str, Any]
) -> Rendered:
    chosen = resolve_locale(locale, variants)
    v = variants[chosen]
    html_src = v.get("html")
    return Rendered(
        locale=chosen,
        subject=render(str(v["subject"]), variables, "subject"),
        text=render(str(v["text"]), variables, "text"),
        html=render(str(html_src), variables, "html") if html_src else None,
    )
