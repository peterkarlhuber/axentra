from __future__ import annotations

import logging

import pytest

from axentra.audit.logging import RedactAuthQuery, install_access_log_redaction, redact_auth_query
from axentra.config.settings import OidcProviderSettings
from axentra.identity.oidc import (
    OidcClient,
    OidcLoginError,
    endpoint_allowed,
    login_error_url,
    pkce_challenge,
    safe_return_to,
)

ORIGINS = ["https://studio.example", "http://localhost:5173"]


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "//evil.example",
        "///evil.example",
        "/\\evil.example",
        "\\/evil.example",
        "/a\\b",
        "https://evil.example/",
        "http://studio.example/",  # scheme differs from the allowed origin
        "https://studio.example.evil/",
        "https://studio.example@evil.example/",
        "https://user:pw@studio.example/",
        "javascript:alert(1)",
        "data:text/html,x",
        "evil.example/path",
        "/path\nX: y",
        "/path\tx",
        "/ path",
        "/a:b/c",
        "/" + "a" * 2001,
        "ftp://studio.example/",
    ],
)
def test_unsafe_return_to_becomes_root(value: str | None) -> None:
    assert safe_return_to(value, ORIGINS) == "/"


@pytest.mark.parametrize(
    "value",
    [
        "/",
        "/app",
        "/app/x?y=1&z=a:b#frag",
        "https://studio.example",
        "https://studio.example/app?x=1",
        "https://STUDIO.example/app",
        "http://localhost:5173/dev",
    ],
)
def test_safe_return_to_is_kept(value: str) -> None:
    assert safe_return_to(value, ORIGINS) == value


def test_wildcard_origin_never_allows_anything() -> None:
    assert safe_return_to("https://evil.example/", ["*"]) == "/"


def test_login_error_url() -> None:
    assert login_error_url("/login", None, "login_failed") == "/login?login_error=login_failed"
    assert login_error_url("/login", "/app", "login_failed") == "/login?login_error=login_failed"
    assert (
        login_error_url("/auth/login?x=1", "https://studio.example/app?q=1", "login_expired")
        == "https://studio.example/auth/login?x=1&login_error=login_expired"
    )
    assert (
        login_error_url("https://studio.example/login", None, "access_denied")
        == "https://studio.example/login?login_error=access_denied"
    )


def test_endpoint_allowed() -> None:
    assert endpoint_allowed("https://idp.example/x", production=True)
    assert endpoint_allowed("http://127.0.0.1:8081/x", production=False)
    assert endpoint_allowed("http://localhost/x", production=False)
    assert not endpoint_allowed("http://127.0.0.1:8081/x", production=True)
    assert not endpoint_allowed("http://idp.example/x", production=False)
    assert not endpoint_allowed("ftp://idp.example/x", production=False)


def _provider(issuer: str) -> OidcProviderSettings:
    return OidcProviderSettings(id="p", name="P", issuer=issuer, client_id="c")


def test_client_refuses_plain_http_issuer() -> None:
    with pytest.raises(OidcLoginError) as err:
        OidcClient(_provider("http://idp.example"), redirect_uri="https://api/cb")
    assert err.value.code == "provider_unavailable"
    with pytest.raises(OidcLoginError):
        OidcClient(_provider("http://127.0.0.1:9000"), redirect_uri="https://api/cb", production=True)
    OidcClient(_provider("http://127.0.0.1:9000"), redirect_uri="http://api/cb").close()


def test_pkce_challenge_rfc7636_example() -> None:
    assert (
        pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    )


def test_access_log_redaction() -> None:
    line = "GET /v1/auth/oidc/x/callback?code=SECRET1&state=SECRET2&foo=bar HTTP/1.1"
    out = redact_auth_query(line)
    assert "SECRET" not in out and "foo=bar" in out and "code=[redacted]" in out
    assert "abc" not in redact_auth_query("/x?setup=abc&invitation=abc&token=abc&id_token=abc")
    install_access_log_redaction()
    install_access_log_redaction()
    access = logging.getLogger("uvicorn.access")
    assert sum(isinstance(f, RedactAuthQuery) for f in access.filters) == 1
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("1.2.3.4", "GET", "/cb?state=S3CR3T&code=C0D3", "1.1", 302),
        None,
    )
    assert RedactAuthQuery().filter(record)
    assert "S3CR3T" not in record.getMessage() and "C0D3" not in record.getMessage()
