"""The content-type policy for blocked file types, per product.

Executable, HTML, SVG and script files (:data:`~axentra.storage.safety.BLOCKED_TYPES`,
:data:`~axentra.storage.safety.BLOCKED_EXTENSIONS`, and content sniffed as one of them, including
any file that starts with a ``#!`` shebang) are *blocked*. What happens to a blocked upload:

- ``refuse`` (installation default unless ``storage.store_blocked_as_inert``): ``415``.
- ``store_inert``: accepted and stored as ``application/octet-stream`` (``stored_inert = true``,
  the type it would have had in ``original_content_type``). Downloads are always attachments with
  ``nosniff``; a blocked file is never served with its real type.

Products override this in their settings (``settings.storage`` of the product)::

    {"storage": {
        "blocked_types": "refuse" | "store_inert",   # default: the installation setting
        "blocked_extensions": ["py", "rb"],          # block more extensions (tighten only)
        "blocked_content_types": ["text/x-python"],  # block more content types (tighten only)
        "inert_extensions": ["html", "sh"]           # accept these as inert even under "refuse"
    }}

The built-in blocklist can never be shortened: a product can only block more, or choose to keep
blocked files as inert attachments instead of refusing them. One rule decides for every reason a
file is blocked (declared type, extension, sniffed content), so a shebang script and a ``.sh`` file
are treated alike: refused, or stored inert when the policy (or ``inert_extensions`` for the file's
extension) says so.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import re
from typing import Any, Literal

from axentra.core.errors import ValidationFailed
from axentra.storage import safety

BlockedTypes = Literal["refuse", "store_inert"]
POLICY_KEYS = ("blocked_types", "blocked_extensions", "blocked_content_types", "inert_extensions")
MAX_ENTRIES = 100
_EXT = re.compile(r"^[a-z0-9][a-z0-9_+-]{0,15}$")


@dataclass(frozen=True, slots=True)
class ContentPolicy:
    """The effective policy of one product."""

    blocked_types: BlockedTypes = "refuse"
    blocked_types_source: Literal["product", "installation"] = "installation"
    blocked_extensions: frozenset[str] = field(default_factory=frozenset)
    """Extra extensions blocked by the product (on top of the built-in list)."""
    blocked_content_types: frozenset[str] = field(default_factory=frozenset)
    inert_extensions: frozenset[str] = field(default_factory=frozenset)

    def extension_blocked(self, ext: str) -> bool:
        return ext in safety.BLOCKED_EXTENSIONS or ext in self.blocked_extensions

    def type_blocked(self, content_type: str | None) -> bool:
        return safety.is_blocked(content_type) or (
            content_type is not None and content_type in self.blocked_content_types
        )

    def store_inert(self, ext: str) -> bool:
        """Whether a blocked file with extension ``ext`` is kept as an inert attachment."""
        return self.blocked_types == "store_inert" or ext in self.inert_extensions


def _list(value: Any, what: str, check: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list) or len(value) > MAX_ENTRIES:
        raise ValidationFailed(f"settings.storage.{what} must be a list of at most {MAX_ENTRIES} strings")
    out = set()
    for entry in value:
        norm = check(entry) if isinstance(entry, str) else None
        if norm is None:
            raise ValidationFailed(f"settings.storage.{what}: invalid entry {entry!r}")
        out.add(norm)
    return frozenset(out)


def _ext(value: str) -> str | None:
    v = value.strip().lower().lstrip(".")
    return v if _EXT.match(v) else None


def parse_policy(storage: Mapping[str, Any] | None, *, installation_inert: bool) -> ContentPolicy:
    """The effective policy from a product's ``settings.storage`` (raises ``ValidationFailed``)."""
    s = storage if isinstance(storage, Mapping) else {}
    mode = s.get("blocked_types")
    if mode is not None and mode not in ("refuse", "store_inert"):
        raise ValidationFailed('settings.storage.blocked_types must be "refuse" or "store_inert"')
    return ContentPolicy(
        blocked_types=mode if mode is not None else ("store_inert" if installation_inert else "refuse"),
        blocked_types_source="product" if mode is not None else "installation",
        blocked_extensions=_list(s.get("blocked_extensions"), "blocked_extensions", _ext),
        blocked_content_types=_list(
            s.get("blocked_content_types"), "blocked_content_types", safety.normalize_content_type
        ),
        inert_extensions=_list(s.get("inert_extensions"), "inert_extensions", _ext),
    )


def check_product_settings(settings: Mapping[str, Any]) -> None:
    """Validate the storage policy keys of product settings (a tenancy settings validator)."""
    storage = settings.get("storage")
    if not isinstance(storage, Mapping):
        return  # no policy keys (other values were never validated; ignored by the service)
    parse_policy(storage, installation_inert=False)


def lenient_policy(storage: Any, *, installation_inert: bool) -> ContentPolicy:
    """Like :func:`parse_policy`, but invalid stored values fall back to the installation default
    for the mode and are ignored for the lists (settings written before validation existed)."""
    try:
        return parse_policy(
            storage if isinstance(storage, Mapping) else None, installation_inert=installation_inert
        )
    except ValidationFailed:
        s = storage if isinstance(storage, Mapping) else {}
        safe: dict[str, Any] = {}
        for key in POLICY_KEYS:
            try:
                parse_policy({key: s.get(key)}, installation_inert=installation_inert)
                safe[key] = s.get(key)
            except ValidationFailed:
                continue
        return parse_policy(safe, installation_inert=installation_inert)
