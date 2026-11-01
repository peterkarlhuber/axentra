"""Outgoing HTTP for webhooks with SSRF protection.

- Only ``https`` URLs (``http`` only outside production with ``events.webhook_allow_http``), no
  credentials in the URL, no fragments.
- The host name is resolved and **every** address is checked: private, loopback, link-local,
  multicast, reserved, unspecified and other non-global addresses are refused unless
  ``events.webhook_allow_private_targets`` is set (tests, development).
- The connection goes to the checked address itself (no second DNS lookup, which defeats DNS
  rebinding); TLS still verifies the certificate for the host name (SNI).
- Redirects are not followed, timeouts apply to connect and every read, and only the first
  ``webhook_response_max_bytes`` of the response body are read.
"""

from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import socket
import ssl
import time
from urllib.parse import urlsplit

from axentra.config.settings import EventsSettings
from axentra.core.errors import ValidationFailed

MAX_URL_LENGTH = 2000
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class TargetRefused(ValidationFailed):
    """The webhook target is not allowed (scheme, host or address)."""


class TargetUnresolvable(TargetRefused):
    """The webhook host name does not resolve (may be temporary)."""


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str


@dataclass(frozen=True)
class HttpResult:
    status: int
    body: str
    duration_ms: int


def _blocked(addr: IPAddress) -> bool:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return (
        not addr.is_global
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def parse_target(url: str, settings: EventsSettings, *, production: bool) -> Target:
    """Static checks of a webhook URL (no DNS); used at creation and before every delivery."""
    if not isinstance(url, str) or len(url) > MAX_URL_LENGTH:
        raise TargetRefused("url must be at most 2000 characters")
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        raise TargetRefused("url is not valid") from None
    scheme = parts.scheme.lower()
    if scheme == "http":
        if production or not settings.webhook_allow_http:
            raise TargetRefused("webhook urls must use https")
    elif scheme != "https":
        raise TargetRefused("webhook urls must use https")
    if parts.username or parts.password:
        raise TargetRefused("webhook urls must not contain credentials")
    if parts.fragment:
        raise TargetRefused("webhook urls must not contain a fragment")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise TargetRefused("webhook urls need a host")
    if not settings.webhook_allow_private_targets:
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            raise TargetRefused("webhook urls must not point to local hosts")
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None and _blocked(literal):
            raise TargetRefused("webhook urls must not point to private, loopback or link-local addresses")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(scheme, host, port or (443 if scheme == "https" else 80), path)


def resolve_target(target: Target, settings: EventsSettings) -> list[str]:
    """Resolve the host and check every address; returns the allowed addresses."""
    try:
        infos = socket.getaddrinfo(target.host, target.port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetUnresolvable(f"cannot resolve {target.host}") from exc
    addrs: list[str] = []
    for info in infos:
        ip = str(info[4][0]).split("%", 1)[0]
        addr = ipaddress.ip_address(ip)
        if _blocked(addr) and not settings.webhook_allow_private_targets:
            raise TargetRefused("the webhook host resolves to a private, loopback or link-local address")
        if ip not in addrs:
            addrs.append(ip)
    if not addrs:
        raise TargetUnresolvable(f"cannot resolve {target.host}")
    return addrs


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip
        self._ctx = context

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self.host)


def post_json(
    url: str,
    body: bytes,
    headers: dict[str, str],
    settings: EventsSettings,
    *,
    production: bool,
    ssl_context: ssl.SSLContext | None = None,
) -> HttpResult:
    """POST ``body`` to ``url`` after the SSRF checks. Raises :class:`TargetRefused` or ``OSError``."""
    target = parse_target(url, settings, production=production)
    addrs = resolve_target(target, settings)
    timeout = settings.webhook_timeout_seconds
    conn: http.client.HTTPConnection
    if target.scheme == "https":
        conn = _PinnedHTTPSConnection(
            target.host, target.port, addrs[0], timeout, ssl_context or ssl.create_default_context()
        )
    else:
        conn = _PinnedHTTPConnection(target.host, target.port, addrs[0], timeout)
    started = time.perf_counter()
    try:
        conn.request("POST", target.path, body=body, headers={**headers, "Content-Length": str(len(body))})
        resp = conn.getresponse()
        limit = settings.webhook_response_max_bytes
        raw = resp.read(limit) if limit else b""
        status = resp.status
    finally:
        conn.close()
    duration = int((time.perf_counter() - started) * 1000)
    return HttpResult(status=status, body=raw.decode("utf-8", errors="replace"), duration_ms=duration)
