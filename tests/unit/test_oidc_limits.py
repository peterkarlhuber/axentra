"""OIDC provider answers are read with a hard size limit, and old ID tokens are refused (MUP-ONA VB-3)."""

from __future__ import annotations

from collections.abc import Iterator
import json
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
import pytest

from axentra.config.settings import OidcProviderSettings
from axentra.identity import oidc
from axentra.identity.oidc import MAX_RESPONSE_BYTES, OidcClient, OidcLoginError

ISSUER = "https://idp.example"
CHUNK = 64 * 1024


class CountingStream(httpx.SyncByteStream):
    """A response body of ``size`` bytes, sent in chunks; ``sent`` counts what the client consumed."""

    def __init__(self, size: int) -> None:
        self.size = size
        self.sent = 0

    def __iter__(self) -> Iterator[bytes]:
        while self.sent < self.size:
            chunk = b" " * min(CHUNK, self.size - self.sent)
            self.sent += len(chunk)
            yield chunk


class FakeProvider:
    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwks_body: CountingStream | None = None
        self.announce_length = False

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "jwks_uri": f"{ISSUER}/jwks",
                },
            )
        if path == "/jwks":
            if self.jwks_body is not None:
                headers = {"Content-Length": str(self.jwks_body.size)} if self.announce_length else {}
                return httpx.Response(200, headers=headers, stream=self.jwks_body)
            jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
            return httpx.Response(200, json={"keys": [{**jwk, "kid": "k1", "alg": "RS256", "use": "sig"}]})
        return httpx.Response(404)

    def token(self, **claims: Any) -> str:
        now = int(time.time())
        body = {"iss": ISSUER, "aud": "client-1", "sub": "s-1", "nonce": "n-1", "iat": now, "exp": now + 300}
        body.update(claims)
        return jwt.encode(body, self.key, algorithm="RS256", headers={"kid": "k1"})


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


def _client(provider: FakeProvider, **settings: Any) -> OidcClient:
    return OidcClient(
        OidcProviderSettings(id="idp", name="IdP", issuer=ISSUER, client_id="client-1", **settings),
        redirect_uri="https://api.example/v1/auth/oidc/idp/callback",
        transport=httpx.MockTransport(provider.handle),
    )


# MUP-ONA T-A7-2
@pytest.mark.parametrize("announce", [False, True], ids=["chunked", "content-length"])
def test_a_2_mib_answer_is_cut_off_after_1_mib(provider: FakeProvider, announce: bool) -> None:
    provider.jwks_body = CountingStream(2 * MAX_RESPONSE_BYTES)
    provider.announce_length = announce
    client = _client(provider)
    with pytest.raises(OidcLoginError, match="too much data") as err:
        client.verify(provider.token(), nonce="n-1")
    assert err.value.code == "provider_unavailable"
    # Read as a stream: at most the limit plus the chunk that crossed it (nothing at all when announced).
    assert provider.jwks_body.sent <= MAX_RESPONSE_BYTES + CHUNK
    if announce:
        assert provider.jwks_body.sent == 0


# MUP-ONA T-A7-2
def test_an_answer_up_to_the_limit_is_read(provider: FakeProvider) -> None:
    jwk = json.loads(RSAAlgorithm.to_jwk(provider.key.public_key()))
    keys = json.dumps({"keys": [{**jwk, "kid": "k1", "alg": "RS256"}]}).encode()
    padded = keys[:-1] + b" " * (MAX_RESPONSE_BYTES - len(keys)) + b"}"
    assert len(padded) == MAX_RESPONSE_BYTES
    original = provider.handle

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/jwks":
            return httpx.Response(200, content=padded)
        return original(request)

    provider.handle = handle  # type: ignore[method-assign]
    assert _client(provider).verify(provider.token(), nonce="n-1")["sub"] == "s-1"


# MUP-ONA T-A7-2
def test_requests_ask_for_an_uncompressed_answer(provider: FakeProvider) -> None:
    seen: list[str] = []
    original = provider.handle

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("accept-encoding", ""))
        return original(request)

    provider.handle = handle  # type: ignore[method-assign]
    _client(provider).verify(provider.token(), nonce="n-1")
    assert seen and set(seen) == {"identity"}


# MUP-ONA T-A7-2
@pytest.mark.parametrize(
    ("age", "max_age", "accepted"),
    [
        (0, 600, True),
        (600, 600, True),
        (600 + oidc.IAT_CLOCK_SKEW_SECONDS - 5, 600, True),  # within the clock skew
        (600 + oidc.IAT_CLOCK_SKEW_SECONDS + 5, 600, False),
        (3600, 600, False),
        (1000, 1800, True),  # configurable per provider
        (1800 + oidc.IAT_CLOCK_SKEW_SECONDS + 5, 1800, False),
    ],
)
def test_id_token_iat_age(provider: FakeProvider, age: int, max_age: int, accepted: bool) -> None:
    client = _client(provider, id_token_max_age_seconds=max_age)
    now = int(time.time())
    token = provider.token(iat=now - age, exp=now + 300)
    if accepted:
        assert client.verify(token, nonce="n-1")["sub"] == "s-1"
    else:
        with pytest.raises(OidcLoginError, match="iat") as err:
            client.verify(token, nonce="n-1")
        assert err.value.code == "login_failed"


# MUP-ONA T-A7-2
def test_id_token_max_age_default_and_bounds() -> None:
    settings = OidcProviderSettings(id="idp", name="IdP", issuer=ISSUER, client_id="c")
    assert settings.id_token_max_age_seconds == 600
    with pytest.raises(ValueError, match="id_token_max_age_seconds"):
        OidcProviderSettings(id="idp", name="IdP", issuer=ISSUER, client_id="c", id_token_max_age_seconds=10)
