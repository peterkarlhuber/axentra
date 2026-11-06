"""Webhook address checks that must not depend on the Python patch level (MUP-ONA MP-A4, PS-4).

``ipaddress.is_global`` changed with the fix for CVE-2024-4032 (Python 3.11.10 / 3.12.4): before it, 6to4
(``2002::/16``) and Teredo (``2001::/32``) addresses counted as global. ``_blocked`` checks those prefixes and
NAT64 explicitly, so the verdicts below hold on every supported version (CI runs them on 3.11, 3.12 and 3.13).
"""

from __future__ import annotations

import ipaddress
import platform

import pytest

from axentra.config.settings import EventsSettings
from axentra.events import http_client
from axentra.events.http_client import TargetRefused, _blocked, parse_target

BLOCKED = True
ALLOWED = False

# (address, verdict, why)
TABLE = [
    # 6to4: embedded private and public IPv4; the whole prefix is refused.
    ("2002:a00:1::", BLOCKED, "6to4 embedding 10.0.0.1"),
    ("2002:7f00:1::1", BLOCKED, "6to4 embedding 127.0.0.1"),
    ("2002:a9fe:a9fe::", BLOCKED, "6to4 embedding 169.254.169.254"),
    ("2002:101:101::1", BLOCKED, "6to4 embedding public 1.1.1.1: whole prefix refused"),
    # Teredo: server 65.54.227.120, client 192.0.2.45 (RFC 4380 example), and private/public clients.
    ("2001:0:4136:e378:8000:63bf:3fff:fdd2", BLOCKED, "Teredo (RFC 4380 example)"),
    ("2001:0:101:101::f5ff:fffe", BLOCKED, "Teredo with client 10.0.0.1"),
    ("2001:0:101:101::fefe:fefe", BLOCKED, "Teredo with public client 1.1.1.1: whole prefix refused"),
    # NAT64 well-known prefix: private embedded IPv4 refused explicitly; the prefix lies in ::/8 (reserved).
    ("64:ff9b::a00:1", BLOCKED, "NAT64 embedding 10.0.0.1"),
    ("64:ff9b::7f00:1", BLOCKED, "NAT64 embedding 127.0.0.1"),
    ("64:ff9b::a9fe:a9fe", BLOCKED, "NAT64 embedding 169.254.169.254"),
    ("64:ff9b::101:101", BLOCKED, "NAT64 embedding public 1.1.1.1: ::/8 is reserved"),
    # NAT64 local-use prefix: refused as a whole.
    ("64:ff9b:1::a00:1", BLOCKED, "NAT64 local-use embedding 10.0.0.1"),
    ("64:ff9b:1:101:1:100::", BLOCKED, "NAT64 local-use /48 embedding public 1.1.1.1"),
    # IPv4-mapped.
    ("::ffff:10.0.0.1", BLOCKED, "IPv4-mapped private"),
    ("::ffff:127.0.0.1", BLOCKED, "IPv4-mapped loopback"),
    ("::ffff:1.1.1.1", ALLOWED, "IPv4-mapped public"),
    # IPv4 special ranges.
    ("100.64.0.1", BLOCKED, "CGNAT 100.64/10"),
    ("169.254.169.254", BLOCKED, "cloud metadata"),
    ("10.0.0.1", BLOCKED, "RFC 1918"),
    ("127.0.0.1", BLOCKED, "loopback"),
    # IPv6 special ranges.
    ("fd00::1", BLOCKED, "unique local fd00::/8"),
    ("fe80::1", BLOCKED, "link-local fe80::/10"),
    ("::1", BLOCKED, "loopback"),
    ("fec0::1", BLOCKED, "site-local (deprecated)"),
    # Public controls.
    ("2606:4700::1111", ALLOWED, "public IPv6"),
    ("1.1.1.1", ALLOWED, "public IPv4"),
]


# MUP-ONA T-AX-NET-1
@pytest.mark.parametrize(("address", "verdict", "why"), TABLE, ids=[row[0] for row in TABLE])
def test_address_verdicts(address: str, verdict: bool, why: str) -> None:
    assert _blocked(ipaddress.ip_address(address)) is verdict, why


# MUP-ONA T-AX-NET-1
@pytest.mark.parametrize(
    ("address", "embedded"),
    [
        ("2002:a00:1::", ["10.0.0.1"]),
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", ["65.54.227.120", "192.0.2.45"]),
        ("64:ff9b::a00:1", ["10.0.0.1"]),
        ("::ffff:10.0.0.1", ["10.0.0.1"]),
        ("2606:4700::1111", []),
    ],
)
def test_embedded_ipv4_extraction(address: str, embedded: list[str]) -> None:
    addr = ipaddress.IPv6Address(address)
    assert [str(a) for a in http_client._embedded_ipv4(addr)] == embedded


# MUP-ONA T-AX-NET-1
def test_prefixes_are_module_constants() -> None:
    assert str(http_client.SIXTO4_PREFIX) == "2002::/16"
    assert str(http_client.TEREDO_PREFIX) == "2001::/32"
    assert str(http_client.NAT64_WELL_KNOWN_PREFIX) == "64:ff9b::/96"
    assert str(http_client.NAT64_LOCAL_USE_PREFIX) == "64:ff9b:1::/48"


# MUP-ONA T-AX-NET-1
def test_verdicts_hold_when_ipaddress_treats_the_tunnel_prefixes_as_global(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulate a Python before the CVE-2024-4032 fix (and one without the ::/8 reservation): the tunnel and
    NAT64 prefixes count as global, not private and not reserved. The explicit prefix checks still refuse them."""
    tunnels = (
        http_client.SIXTO4_PREFIX,
        http_client.TEREDO_PREFIX,
        http_client.NAT64_WELL_KNOWN_PREFIX,
        http_client.NAT64_LOCAL_USE_PREFIX,
    )
    cls = ipaddress.IPv6Address

    def overriding(name: str, value: bool) -> property:
        original = getattr(cls, name)

        def get(self: ipaddress.IPv6Address) -> bool:
            if any(self in net for net in tunnels):
                return value
            return bool(original.__get__(self, cls))

        return property(get)

    monkeypatch.setattr(cls, "is_global", overriding("is_global", True))
    monkeypatch.setattr(cls, "is_private", overriding("is_private", False))
    monkeypatch.setattr(cls, "is_reserved", overriding("is_reserved", False))
    assert ipaddress.ip_address("2002:a00:1::").is_global  # the simulation is active

    for address in (
        "2002:a00:1::",
        "2002:101:101::1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        "64:ff9b::a00:1",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b:1::a00:1",
        "64:ff9b:1:101:1:100::",
    ):
        assert _blocked(ipaddress.ip_address(address)), address
    # A NAT64 address of a public IPv4 host is judged by is_global/is_reserved only (simulated as global here).
    assert not _blocked(ipaddress.ip_address("64:ff9b::101:101"))


# MUP-ONA T-AX-NET-1
@pytest.mark.parametrize("host", ["[2002:a00:1::]", "[2001:0:101:101::f5ff:fffe]", "[64:ff9b::a00:1]"])
def test_literal_tunnel_addresses_are_refused_in_urls(host: str) -> None:
    with pytest.raises(TargetRefused):
        parse_target(f"https://{host}/hook", EventsSettings(), production=True)


# MUP-ONA T-AX-NET-2
def test_python_version_is_reported() -> None:
    """CI runs this module on 3.11, 3.12 and 3.13 (current patch levels); the version goes into the log."""
    print(f"T-AX-NET-2 python {platform.python_version()}")
    assert platform.python_version_tuple()[0] == "3"
