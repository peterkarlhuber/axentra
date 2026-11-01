"""File name sanitizing, content type normalization and sniffing, safe download headers.

Display names are never used to build storage paths (keys are derived from ids only); they are
still cleaned because they end up in ``Content-Disposition`` headers, logs and UIs.

Content types: the type a client declares is a hint. The first bytes of the upload are sniffed
for a small set of well-known signatures. Executable, HTML, SVG and script types are refused at
upload (by declared type, by file name extension and by sniffed content), and downloads are always
served as attachments with ``X-Content-Type-Options: nosniff`` and a safe ``Content-Type``.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import quote

MAX_NAME_BYTES = 255
SNIFF_BYTES = 512
OCTET_STREAM = "application/octet-stream"

#: Types that are never stored (and never served inline anyway).
BLOCKED_TYPES = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
        "image/svg+xml",
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "text/ecmascript",
        "application/x-msdownload",
        "application/x-msdos-program",
        "application/x-dosexec",
        "application/vnd.microsoft.portable-executable",
        "application/x-executable",
        "application/x-elf",
        "application/x-mach-binary",
        "application/x-sharedlib",
        "application/x-sh",
        "application/x-csh",
        "text/x-shellscript",
        "application/x-bat",
        "application/x-msi",
        "application/hta",
        "application/x-httpd-php",
        "text/x-php",
        "application/java-archive",
        "application/x-java-applet",
        "text/xml-external-parsed-entity",
    }
)

BLOCKED_EXTENSIONS = frozenset(
    {
        "html", "htm", "xhtml", "xht", "shtml", "svg", "svgz", "js", "mjs", "cjs", "exe", "dll", "com",
        "scr", "msi", "bat", "cmd", "ps1", "vbs", "vbe", "wsf", "hta", "sh", "csh", "php", "jar",
        "app", "elf",
    }
)  # fmt: skip

_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$")
_RESERVED = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]')
_SPACES = re.compile(r"\s+")

# (signature, offset, content type); checked in order.
_SIGNATURES: tuple[tuple[bytes, int, str], ...] = (
    (b"MZ", 0, "application/x-msdownload"),
    (b"\x7fELF", 0, "application/x-executable"),
    (b"\xcf\xfa\xed\xfe", 0, "application/x-mach-binary"),
    (b"\xce\xfa\xed\xfe", 0, "application/x-mach-binary"),
    (b"\xfe\xed\xfa\xcf", 0, "application/x-mach-binary"),
    (b"\xfe\xed\xfa\xce", 0, "application/x-mach-binary"),
    (b"\xca\xfe\xba\xbe", 0, "application/x-mach-binary"),
    (b"#!", 0, "application/x-sh"),
    (b"\x89PNG\r\n\x1a\n", 0, "image/png"),
    (b"\xff\xd8\xff", 0, "image/jpeg"),
    (b"GIF87a", 0, "image/gif"),
    (b"GIF89a", 0, "image/gif"),
    (b"%PDF-", 0, "application/pdf"),
    (b"PK\x03\x04", 0, "application/zip"),
    (b"\x1f\x8b", 0, "application/gzip"),
)
_HTML_MARKERS = (
    b"<!doctype html",
    b"<html",
    b"<head",
    b"<body",
    b"<script",
    b"<iframe",
    b"<svg",
    b"<object",
    b"<embed",
    b"<meta",
    b"<link",
    b"<style",
)


def sanitize_name(name: str | None) -> str:
    """A display name: last path segment, no control/reserved characters, at most 255 UTF-8 bytes."""
    raw = unicodedata.normalize("NFC", name or "")
    raw = raw.replace("\\", "/").rsplit("/", 1)[-1]
    raw = "".join(ch for ch in raw if unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn"))
    raw = _RESERVED.sub("_", raw)
    raw = _SPACES.sub(" ", raw).strip().rstrip(". ")
    if not raw or set(raw) <= {"."}:
        return "file"
    if len(raw.encode()) > MAX_NAME_BYTES:
        stem, dot, ext = raw.rpartition(".")
        if dot and 0 < len(ext.encode()) <= 16:
            budget = MAX_NAME_BYTES - len(ext.encode()) - 1
            raw = _truncate_utf8(stem, budget) + "." + ext
        else:
            raw = _truncate_utf8(raw, MAX_NAME_BYTES)
    return raw


def _truncate_utf8(text: str, max_bytes: int) -> str:
    return text.encode()[:max_bytes].decode("utf-8", "ignore")


def extension(name: str) -> str:
    _, dot, ext = name.rpartition(".")
    return ext.lower() if dot else ""


def normalize_content_type(value: str | None) -> str | None:
    """``type/subtype`` in lowercase without parameters, or None when missing or malformed."""
    if not value:
        return None
    base = value.split(";", 1)[0].strip().lower()
    return base if _TYPE.match(base) else None


def sniff(head: bytes) -> str | None:
    """The content type implied by the first bytes, for a small set of signatures."""
    for sig, offset, ctype in _SIGNATURES:
        if head[offset : offset + len(sig)] == sig:
            return ctype
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    text = head.lstrip(b"\xef\xbb\xbf\xfe\xff\x00 \t\r\n\x0c").lower().replace(b"\x00", b"")
    if text.startswith(_HTML_MARKERS):
        return "image/svg+xml" if text.startswith(b"<svg") else "text/html"
    if text.startswith(b"<?xml") or text.startswith(b"<!doctype svg"):
        if b"<svg" in text:
            return "image/svg+xml"
        if b"<html" in text or b"xhtml" in text:
            return "application/xhtml+xml"
        return "application/xml"
    if text.startswith(b"<!--") and any(m in text for m in (b"<html", b"<script", b"<svg")):
        return "text/html"
    return None


def is_blocked(content_type: str | None) -> bool:
    return content_type is not None and content_type in BLOCKED_TYPES


def choose_content_type(declared: str | None, sniffed: str | None) -> str:
    """Sniffed wins when the declared type is missing, generic or of another top-level type."""
    if sniffed is None:
        return declared or OCTET_STREAM
    if declared is None or declared == OCTET_STREAM:
        return sniffed
    if declared.split("/", 1)[0] != sniffed.split("/", 1)[0]:
        return sniffed
    return declared


def type_allowed(content_type: str, allowed: list[str]) -> bool:
    """Empty allow-list: everything allowed. Entries are exact types or ``type/*``."""
    if not allowed:
        return True
    top = content_type.split("/", 1)[0]
    for entry in allowed:
        e = entry.strip().lower()
        if e == content_type or e == "*/*" or (e.endswith("/*") and e[:-2] == top):
            return True
    return False


_INLINE_RISKY = re.compile(r"(html|xml|svg|script|javascript|ecmascript|x-sh|php)", re.IGNORECASE)


def served_content_type(content_type: str) -> str:
    """The Content-Type used for downloads: the stored type unless it is risky, else octet-stream."""
    norm = normalize_content_type(content_type)
    if norm is None or is_blocked(norm) or _INLINE_RISKY.search(norm):
        return OCTET_STREAM
    return norm


def content_disposition(name: str) -> str:
    """``attachment`` with an ASCII fallback and an RFC 5987 UTF-8 name; header-injection safe."""
    clean = sanitize_name(name)
    ascii_name = unicodedata.normalize("NFKD", clean).encode("ascii", "ignore").decode()
    ascii_name = re.sub(r"[^A-Za-z0-9 ._()\[\]+-]", "_", ascii_name).strip() or "file"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(clean, safe='')}"
