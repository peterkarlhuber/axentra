"""The webhook attempt's time budget includes the DNS lookup (MUP-ONA VB-5)."""

from __future__ import annotations

from collections.abc import Iterator
import socket
import threading
import time
from typing import Any

import pytest

from axentra.config.settings import EventsSettings
from axentra.events import http_client
from axentra.events.http_client import TargetUnresolvable, post_json

TOLERANCE = 1.5


@pytest.fixture
def slow_resolver(monkeypatch: pytest.MonkeyPatch) -> Iterator[threading.Event]:
    """A resolver that needs 10 s for every lookup (released when the test ends)."""
    release = threading.Event()

    def getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        release.wait(10)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    yield release
    release.set()


# MUP-ONA T-A7-4
def test_slow_dns_is_cut_off_at_the_budget(slow_resolver: threading.Event) -> None:
    settings = EventsSettings(webhook_timeout_seconds=5)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match=r"resolving hooks\.example\.com"):
        post_json("https://hooks.example.com/x", b"{}", {}, settings, production=True)
    assert time.monotonic() - started <= 5 + TOLERANCE


# MUP-ONA T-A7-4
def test_lookup_within_the_budget_returns_its_result(monkeypatch: pytest.MonkeyPatch) -> None:
    def getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    infos = http_client._getaddrinfo("hooks.example.com", 443, 1.0)
    assert infos[0][4] == ("93.184.216.34", 443)


# MUP-ONA T-A7-4
def test_resolver_errors_still_mean_unresolvable(monkeypatch: pytest.MonkeyPatch) -> None:
    def getaddrinfo(host: str, port: int, *args: Any, **kwargs: Any) -> list[Any]:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    target = http_client.parse_target("https://nowhere.example.com/", EventsSettings(), production=True)
    with pytest.raises(TargetUnresolvable):
        http_client.resolve_target(target, EventsSettings(), timeout=1.0)
