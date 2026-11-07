"""``axentra remote`` helpers that need no server."""

from __future__ import annotations

import pytest

from axentra.api.context import SESSION_COOKIE_DEV, SESSION_COOKIE_SECURE
from axentra.remote import _SESSION_COOKIES, RemoteClient, RemoteError, _session_token


def test_session_cookie_names_match_the_api() -> None:
    assert set(_SESSION_COOKIES) == {SESSION_COOKIE_SECURE, SESSION_COOKIE_DEV}


def test_session_token_is_read_from_the_right_cookie() -> None:
    headers = [
        ("Content-Type", "application/json"),
        ("Set-Cookie", "axentra-login=x; Path=/"),
        ("Set-Cookie", '__Host-axentra-session="tok123"; HttpOnly; Secure; Path=/; SameSite=Lax'),
    ]
    assert _session_token(headers) == "tok123"
    assert _session_token([("Set-Cookie", "other=1")]) is None


@pytest.mark.parametrize("url", ["ftp://x", "example.com", "http://", "javascript:alert(1)"])
def test_only_absolute_http_urls(url: str) -> None:
    with pytest.raises(RemoteError) as info:
        RemoteClient(url)
    assert info.value.code == "invalid_url"
    assert RemoteClient("https://api.example.com/").base_url == "https://api.example.com"
