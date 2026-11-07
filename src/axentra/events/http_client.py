"""Outgoing HTTP for webhooks with SSRF protection.

- Only ``https`` URLs (``http`` only outside production with ``events.webhook_allow_http``), no
  credentials in the URL, no fragments.
- The host name is resolved and **every** address is checked: private, loopback, link-local,
  multicast, reserved, unspecified and other non-global addresses are refused unless
  ``events.webhook_allow_private_targets`` is set (tests, development). IPv6 addresses that lead to
  an IPv4 address (IPv4-mapped, 6to4, Teredo, NAT64) are judged by that address, and the 6to4,
  Teredo and NAT64 local-use prefixes are refused as a whole, on every Python patch level.
- The connection goes to the checked address itself (no second DNS lookup, which defeats DNS
  rebinding); TLS still verifies the certificate for the host name (SNI).
- Redirects are not followed and only the first ``webhook_response_max_bytes`` of the response
  body are read. ``webhook_timeout_seconds`` is the **total** budget of one attempt (connect, TLS
  handshake, sending, response headers and body) and includes the DNS lookup: a slow resolver or a
  receiver that answers slowly byte by byte is cut off at the deadline, so one delivery never holds
  a worker longer than the timeout.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from axentra.config.settings import EventsSettings
from axentra.core.errors import ValidationFailed

MAX_URL_LENGTH = 2000
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
#: A host made only of numeric labels (decimal, octal or 0x hex) that is not a canonical IPv4 address.
_NUMERIC_HOST = re.compile(r"(?:(?:0x[0-9a-f]*|[0-9]+)\.?){1,4}")
#: Characters no host name contains (whitespace, control characters, percent-encoding, brackets).
_INVALID_HOST_CHARS = re.compile(r"[\s\x00-\x1f\x7f%\[\]\\/@]")


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


#: IPv6 prefixes that carry an IPv4 address are checked explicitly, not through ``is_global``: its answer for
#: them depends on the Python patch level (before the CVE-2024-4032 fix, 3.11.10 / 3.12.4, ``2002::/16`` counted
#: as global), and it treats NAT64 addresses as global whatever IPv4 address they lead to (MUP-ONA PS-4).
#: 6to4 (RFC 3056) and Teredo (RFC 4380): deprecated tunnels whose relays forward to the embedded IPv4
#: address; the embedded addresses are checked and the whole prefix is refused (no webhook receiver needs it).
SIXTO4_PREFIX = ipaddress.IPv6Network("2002::/16")
TEREDO_PREFIX = ipaddress.IPv6Network("2001::/32")
#: NAT64 well-known prefix (RFC 6052): the gateway connects to the IPv4 address in the last 32 bits.
NAT64_WELL_KNOWN_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
#: NAT64 local-use prefix (RFC 8215): the IPv4 address sits where the operator's prefix length puts it, so
#: every RFC 6052 position is checked; the prefix is not globally reachable and is refused as a whole as well.
NAT64_LOCAL_USE_PREFIX = ipaddress.IPv6Network("64:ff9b:1::/48")
#: Prefixes refused whatever IPv4 address they embed.
REFUSED_IPV6_PREFIXES = (SIXTO4_PREFIX, TEREDO_PREFIX, NAT64_LOCAL_USE_PREFIX)


def _embedded_ipv4(addr: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """The IPv4 addresses an IPv6 address leads to: IPv4-mapped, 6to4, Teredo server and client, NAT64."""
    found: list[ipaddress.IPv4Address] = []
    if addr.ipv4_mapped is not None:
        found.append(addr.ipv4_mapped)
    if addr in SIXTO4_PREFIX:
        found.append(ipaddress.IPv4Address((int(addr) >> 80) & 0xFFFFFFFF))  # bits 16-47
    if addr in TEREDO_PREFIX and addr.teredo is not None:
        found.extend(
            addr.teredo
        )  # (server, client); the client address is stored inverted, .teredo undoes it
    if addr in NAT64_WELL_KNOWN_PREFIX:
        found.append(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF))
    if addr in NAT64_LOCAL_USE_PREFIX:
        # RFC 6052 section 2.2: prefix length /48 (bits 48-63 and 72-87, bits 64-71 are zero), /56 (56-63 and
        # 72-95), /64 (72-103) and /96 (96-127).
        b = addr.packed
        for octets in (b[6:8] + b[9:11], b[7:8] + b[9:12], b[9:13], b[12:16]):
            found.append(ipaddress.IPv4Address(octets))
    return found


def _blocked(addr: IPAddress) -> bool:
    """``True`` when a webhook must not connect to ``addr`` (fail closed)."""
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return _blocked(addr.ipv4_mapped)
        if any(_blocked(v4) for v4 in _embedded_ipv4(addr)):
            return True
        if any(addr in prefix for prefix in REFUSED_IPV6_PREFIXES):
            return True
    return (
        not addr.is_global
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or (isinstance(addr, ipaddress.IPv6Address) and addr.is_site_local)  # deprecated fec0::/10
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
        if literal is None and _NUMERIC_HOST.fullmatch(host):
            # Legacy IPv4 notations (2130706433, 0x7f.1, 0177.0.0.1, 127.1, 0): the resolver turns
            # them into addresses that the delivery-time check refuses anyway; refuse them up front.
            raise TargetRefused("webhook urls must use a host name or a dotted-decimal IPv4 address")
        if _INVALID_HOST_CHARS.search(host):
            raise TargetRefused("url is not valid")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(scheme, host, port or (443 if scheme == "https" else 80), path)


def _getaddrinfo(host: str, port: int, timeout: float | None) -> list[Any]:
    """``socket.getaddrinfo`` that gives up after ``timeout`` seconds (``None``: no limit).

    The system resolver has no timeout parameter, so the lookup runs in a daemon thread and the caller stops
    waiting at the limit (MUP-ONA VB-5). An abandoned lookup ends when the resolver's own timeout does; its
    result is dropped."""
    if timeout is None:
        return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    outcome: dict[str, Any] = {}

    def lookup() -> None:
        try:
            outcome["infos"] = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except BaseException as exc:  # handed to the caller below
            outcome["error"] = exc

    worker = threading.Thread(target=lookup, name="axentra-webhook-dns", daemon=True)
    worker.start()
    worker.join(max(timeout, 0.0))
    if worker.is_alive():
        raise TimeoutError(f"resolving {host} took longer than {timeout:g} s")
    if "error" in outcome:
        raise outcome["error"]
    infos: list[Any] = outcome["infos"]
    return infos


def resolve_target(target: Target, settings: EventsSettings, *, timeout: float | None = None) -> list[str]:
    """Resolve the host and check every address; returns the allowed addresses. With ``timeout`` the
    lookup raises :class:`TimeoutError` when it takes longer."""
    try:
        infos = _getaddrinfo(target.host, target.port, timeout)
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


class _Deadline:
    """Aborts a connection's socket when the total time budget of an attempt is used up.

    Socket timeouts bound each single operation only, so a receiver that sends one byte just
    before every timeout could keep a delivery open for hours. A timer shuts the socket down at
    the deadline, which makes any blocked connect/send/recv return at once."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self.expired = False
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._done = False
        self._timer = threading.Timer(seconds, self._expire)
        self._timer.daemon = True

    def start(self) -> None:
        self._timer.start()

    def watch(self, sock: socket.socket) -> None:
        with self._lock:
            self._sock = sock
            expired = self.expired
        if expired:
            self._shutdown(sock)

    def _expire(self) -> None:
        with self._lock:
            if self._done:
                return
            self.expired = True
            sock = self._sock
        if sock is not None:
            self._shutdown(sock)

    @staticmethod
    def _shutdown(sock: socket.socket) -> None:
        # The plain socket method also for TLS sockets: no TLS state change from this thread.
        with contextlib.suppress(OSError):
            socket.socket.shutdown(sock, socket.SHUT_RDWR)

    def cancel(self) -> bool:
        """Stop the timer; ``True`` when the deadline had already expired."""
        with self._lock:
            self._done = True
        self._timer.cancel()
        return self.expired


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float, deadline: _Deadline) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ip = ip
        self._deadline = deadline

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)
        self._deadline.watch(self.sock)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self, host: str, port: int, ip: str, timeout: float, context: ssl.SSLContext, deadline: _Deadline
    ) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip
        self._ctx = context
        self._deadline = deadline

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        tls = self._ctx.wrap_socket(sock, server_hostname=self.host, do_handshake_on_connect=False)
        self.sock = tls
        self._deadline.watch(tls)
        tls.do_handshake()


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
    timeout = settings.webhook_timeout_seconds
    # The budget covers the DNS lookup too (MUP-ONA VB-5): a slow resolver cannot hold the worker longer.
    started = time.perf_counter()
    addrs = resolve_target(target, settings, timeout=timeout)
    remaining = timeout - (time.perf_counter() - started)
    if remaining <= 0:
        raise TimeoutError(f"no complete response within {timeout:g} s")
    deadline = _Deadline(remaining)
    conn: http.client.HTTPConnection
    if target.scheme == "https":
        conn = _PinnedHTTPSConnection(
            target.host,
            target.port,
            addrs[0],
            timeout,
            ssl_context or ssl.create_default_context(),
            deadline,
        )
    else:
        conn = _PinnedHTTPConnection(target.host, target.port, addrs[0], timeout, deadline)
    deadline.start()
    try:
        try:
            conn.request(
                "POST", target.path, body=body, headers={**headers, "Content-Length": str(len(body))}
            )
            resp = conn.getresponse()
            limit = settings.webhook_response_max_bytes
            raw = resp.read(limit) if limit else b""
            status = resp.status
        except (OSError, http.client.HTTPException) as exc:
            if deadline.cancel():
                raise TimeoutError(f"no complete response within {timeout:g} s") from exc
            raise
        if deadline.cancel():
            raise TimeoutError(f"no complete response within {timeout:g} s")
    finally:
        deadline.cancel()
        conn.close()
    duration = int((time.perf_counter() - started) * 1000)
    return HttpResult(status=status, body=raw.decode("utf-8", errors="replace"), duration_ms=duration)
