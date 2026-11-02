from __future__ import annotations

import json
import logging
from urllib.parse import quote

import pytest

from axentra.audit.logging import RedactAuthQuery, install_access_log_redaction, redact_auth_query
from axentra.config.settings import OidcProviderSettings
from axentra.core.redaction import carries_secret, redact, redact_text, strip_secret_params
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


# -- encoded secrets (security review round 3, NF-2) -------------------------------------------------

TOKEN = "axinv_" + "Q" * 20 + "-_" + "w" * 21


def _spellings(value: str) -> list[str]:
    once = quote(value, safe="")
    return [value, once, quote(once, safe=""), value.replace("_", "%5F"), value.replace("_", "%5f")]


@pytest.mark.parametrize(
    "line",
    [
        "/v1/auth/oidc/x/start?return_to=%2Finvitations%2Faccept%2F%3Ftoken%3DS3CR3T HTTP/1.1",
        "/v1/auth/oidc/x/start?return_to=http%3A%2F%2Fstudio%2FINVITATIONS%2Faccept%3Fa%3D1%26token%3DS3CR3T",
        "/v1/auth/oidc/x/start?return_to=%252Fx%253Ftoken%253DS3CR3T",
        "/v1/auth/oidc/x/start?return_to=%2Fx%3Fid_token%3DS3CR3T&x=1",
        "/v1/auth/oidc/x/start?return_to=%2Fx%3fToKeN%3dS3CR3T",
        "/v1/auth/oidc/x/start?return_to=%2Fx%3F%74oken%3DS3CR3T",
        "/v1/auth/oidc/x/start?return_to=%2Fx%3Finvitation%3DS3CR3T",
        "/v1/auth/oidc/x/start?invitation=S3CR3T",
        "/v1/auth/oidc/x/start?a=1&setup_token=S3CR3T",
    ],
)
def test_access_log_redaction_of_encoded_query_values(line: str) -> None:
    out = redact_auth_query(line)
    assert "S3CR3T" not in out and "[redacted]" in out
    assert out.startswith("/v1/auth/oidc/x/start?")


def test_invitation_tokens_are_redacted_in_every_spelling() -> None:
    for spelling in _spellings(TOKEN):
        for text in (spelling, f"/x?return_to=%2Fa%3Fnext%3D{spelling}", f"link {spelling} sent"):
            assert TOKEN[6:] not in redact_text(text) and TOKEN[6:] not in redact_auth_query(text)
            assert quote(TOKEN[6:], safe="") not in redact_text(text)
    # Audit details go through redact(): the URL value loses the token, the rest stays.
    out = redact({"url": f"https://studio/invitations/accept/?token={quote(TOKEN, safe='')}&tab=2"})
    assert TOKEN[6:] not in json.dumps(out) and "tab=2" in out["url"]
    # Plain query values that are no secrets stay readable.
    assert redact_text("/x?state=open&code=7&page=2") == "/x?state=open&code=7&page=2"


def test_uvicorn_access_record_with_encoded_return_to_is_redacted() -> None:
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        (
            "1.2.3.4",
            "GET",
            "/v1/auth/oidc/c/start?return_to=http%3A%2F%2Fs%2Finvitations%2Faccept%2F%3Ftoken%3D" + TOKEN,
            "1.1",
            302,
        ),
        None,
    )
    assert RedactAuthQuery().filter(record)
    assert TOKEN[6:] not in record.getMessage() and "return_to=http%3A%2F%2Fs%2F" in record.getMessage()


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("/invitations/accept?token=T", "/invitations/accept"),
        ("/invitations/accept/?token=T", "/invitations/accept/"),
        ("/INVITATIONS/ACCEPT?Token=T", "/INVITATIONS/ACCEPT"),
        ("/invitations/accept?a=1&token=T&b=%2F2#h", "/invitations/accept?a=1&b=%2F2#h"),
        ("/x?%74oken=T", "/x"),
        ("/x?id%5Ftoken=T", "/x"),
        ("/x?setup=T&invitation=T&password=T&api_key=T", "/x"),
        (f"/x?n={quote(TOKEN, safe='')}", "/x"),
        (f"/x?n={TOKEN.replace('_', '%255F')}", "/x"),
        ("/x?return_to=%2Fa%3Ftoken%3DT&keep=1", "/x?keep=1"),
        ("/x?return_to=%252Fa%253Ftoken%253DT", "/x"),
        ("/x#token=T", "/x"),
        ("/x#section-2", "/x#section-2"),
        ("/a%3Ftoken%3DT", "/"),
        ("https://studio.example/a%3Ftoken%3DT?x=1", "https://studio.example/"),
        ("https://studio.example/i/a?token=T", "https://studio.example/i/a"),
        ("/x?state=open&code=1&q=a+b", "/x?state=open&code=1&q=a+b"),
        ("/x?", "/x?"),
        ("/plain", "/plain"),
    ],
)
def test_strip_secret_params(url: str, expected: str) -> None:
    out, removed = strip_secret_params(url)
    assert out == expected
    assert bool(removed) == (out != url)


def test_stored_return_to_adopts_only_invitation_tokens() -> None:
    assert carries_secret(f"/a?b={quote(quote(TOKEN, safe=''), safe='')}")
    assert not carries_secret("/a?b=c&state=open")
    _, removed = strip_secret_params(f"/i/a/?token={quote(TOKEN, safe='')}&x=1")
    assert removed == [("token", TOKEN)]
