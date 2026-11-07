"""Shared security test vectors against Axentra's webhook address check, OIDC client and redaction (MUP-ONA MP-A8).

``tests/vectors/security-vectors.json`` is a vendored copy of a corpus maintained outside this repository;
``tests/vectors/SOURCE.md`` names its origin, version and SHA-256, and the first test here checks that the copy is
exactly the recorded one. Nothing here imports or reads anything outside this repository. A vector Axentra judges
differently from the corpus is listed in ``known_differences`` (platform ``axentra``) with its reason; the test then
asserts the listed verdict, so a difference that disappears fails until its entry is removed.

Egress: an ``address`` goes to ``_blocked``; a ``url`` goes the way a webhook target does (``parse_target`` in
production, then ``resolve_target`` with a fake resolver). JWT: ``OidcClient.verify`` against a provider served by
``httpx.MockTransport`` with keys generated here. Redaction: ``redact``.
"""

from __future__ import annotations

import base64
from collections import Counter
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
import httpx
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm, get_default_algorithms
import pytest

from axentra.config.settings import EventsSettings, OidcProviderSettings
from axentra.core.redaction import redact
from axentra.events import http_client
from axentra.events.http_client import TargetRefused, parse_target, resolve_target
from axentra.identity.oidc import OidcClient, OidcLoginError

PLATFORM = "axentra"
VECTORS = Path(__file__).parent / "vectors"
CORPUS_PATH = VECTORS / "security-vectors.json"
CORPUS: dict[str, Any] = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
CATEGORIES = ("egress", "jwt", "redaction")
VERDICTS = {"egress": {"block", "allow"}, "jwt": {"accept", "reject"}, "redaction": {"not_redacted"}}
DIFFERENCES = {
    (item["category"], item["id"]): item
    for item in CORPUS["known_differences"]
    if item["platform"] == PLATFORM
}


def _vectors(category: str) -> list[Any]:
    return [pytest.param(vector, id=vector["id"]) for vector in CORPUS[category]]


def _expected(category: str, vector: dict[str, Any]) -> str:
    difference = DIFFERENCES.get((category, vector["id"]))
    return str(difference["actual"] if difference else vector["expect"])


# ---- the copy and the corpus ---------------------------------------------------------------------------------------


# MUP-ONA T-VEC-2
def test_the_copy_is_the_recorded_version() -> None:
    source = (VECTORS / "SOURCE.md").read_text(encoding="utf-8")
    recorded = re.search(r"^SHA-256: `([0-9a-f]{64})`$", source, re.MULTILINE)
    version = re.search(r"^Version: `(\d+)`$", source, re.MULTILINE)
    assert recorded and version, "tests/vectors/SOURCE.md must name the Version and the SHA-256 of the copy"
    actual = hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest()
    assert actual == recorded.group(1), (
        "tests/vectors/security-vectors.json differs from the copy recorded in tests/vectors/SOURCE.md: replace it "
        "with the canonical file named there and record its version and SHA-256; never edit the copy by hand"
    )
    assert int(version.group(1)) == CORPUS["version"]


# MUP-ONA T-VEC-2
def test_the_corpus_is_well_formed() -> None:
    assert isinstance(CORPUS["version"], int)
    assert CORPUS["version"] >= 1
    ids = Counter(vector["id"] for category in CATEGORIES for vector in CORPUS[category])
    assert [name for name, count in ids.items() if count > 1] == []
    known = {(category, vector["id"]): vector for category in CATEGORIES for vector in CORPUS[category]}
    for item in CORPUS["known_differences"]:
        assert (item["category"], item["id"]) in known, item
        assert item["actual"] in VERDICTS[item["category"]], item
        assert item["actual"] != known[(item["category"], item["id"])].get("expect"), item
        assert len(item["reason"]) > 30, item


# ---- egress --------------------------------------------------------------------------------------------------------


def axentra_egress(vector: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> str:
    """``block`` or ``allow``: Axentra's verdict on an egress vector (a production webhook target)."""
    if "address" in vector:
        return "block" if http_client._blocked(ipaddress.ip_address(vector["address"])) else "allow"

    def getaddrinfo(host: str, port: int, timeout: float | None) -> list[Any]:
        if "resolves_to" in vector:
            answers = list(vector["resolves_to"])
        elif ":" in host:  # an IPv6 literal resolves to itself
            answers = [host]
        else:  # the C library's reading of a numeric host (2130706433, 0x7f.1, 0177.0.0.1, 127.1)
            try:
                answers = [str(ipaddress.IPv4Address(socket.inet_aton(host)))]
            except OSError:
                raise AssertionError(f"{vector['id']}: the host {host} needs resolves_to") from None
        return [
            (socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
            for a in answers
        ]

    monkeypatch.setattr(http_client, "_getaddrinfo", getaddrinfo)
    settings = EventsSettings()
    try:
        target = parse_target(vector["url"], settings, production=True)
        resolve_target(target, settings, timeout=5.0)
    except TargetRefused:
        return "block"
    return "allow"


# MUP-ONA T-VEC-2
@pytest.mark.parametrize("vector", _vectors("egress"))
def test_egress_vector(vector: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    assert axentra_egress(vector, monkeypatch) == _expected("egress", vector), vector["note"]


# ---- jwt -----------------------------------------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class Keys:
    """The keys the vectors' ``key_ref`` names, generated for this test run (no real keys)."""

    def __init__(self) -> None:
        self.private: dict[str, Any] = {
            "rsa-a": rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "ec-p256": ec.generate_private_key(ec.SECP256R1()),
            "ed25519": ed25519.Ed25519PrivateKey.generate(),
            "rsa-unpublished": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        }
        self.shared = secrets.token_bytes(32)
        self.rsa_a_public_pem = (
            self.private["rsa-a"]
            .public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        )

    def jwks(self) -> dict[str, Any]:
        """The provider's published key set: rsa-a, ec-p256 and ed25519 (with their names as kid)."""
        published = (("rsa-a", RSAAlgorithm), ("ec-p256", ECAlgorithm), ("ed25519", OKPAlgorithm))
        keys = []
        for name, algorithm in published:
            jwk = json.loads(algorithm.to_jwk(self.private[name].public_key()))
            keys.append({**jwk, "kid": name, "use": "sig"})
        return {"keys": keys}

    def sign(self, signing_input: bytes, alg: str, key_ref: str) -> bytes:
        if key_ref == "none":
            return b""
        if key_ref in ("hmac-shared", "hmac-rsa-a-public"):
            secret = self.shared if key_ref == "hmac-shared" else self.rsa_a_public_pem
            digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
            return hmac.new(secret, signing_input, digest).digest()
        algorithm = get_default_algorithms()[alg]
        signature: bytes = algorithm.sign(signing_input, self.private[key_ref])
        return signature


def resolve_claims(value: Any, context: dict[str, Any], now: int) -> Any:
    """The corpus placeholders: ``@issuer``, ``@client_id``, ``@nonce``, ``@now`` and ``@now+N`` / ``@now-N``."""
    if isinstance(value, list):
        return [resolve_claims(item, context, now) for item in value]
    if isinstance(value, dict):
        return {name: resolve_claims(item, context, now) for name, item in value.items()}
    if isinstance(value, str) and value.startswith("@"):
        moment = re.fullmatch(r"@now(?:([+-])(\d+))?", value)
        if moment:
            offset = int(moment.group(2) or 0)
            return now - offset if moment.group(1) == "-" else now + offset
        return context[value[1:]]
    return value


def build_token(vector: dict[str, Any], keys: Keys, context: dict[str, Any]) -> str:
    header = dict(vector["header"])
    claims = resolve_claims(vector["claims"], context, int(time.time()))
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}".encode()
    signature = keys.sign(signing_input, header["alg"], vector["key_ref"])
    if vector.get("tamper") == "signature":
        signature = bytes([signature[0] ^ 0x01]) + signature[1:]
    return f"{signing_input.decode()}.{_b64(signature)}"


@pytest.fixture(scope="module")
def keys() -> Keys:
    return Keys()


def axentra_jwt(vector: dict[str, Any], keys: Keys) -> str:
    """``accept`` or ``reject``: Axentra's verdict on a jwt vector."""
    context = CORPUS["jwt_context"]
    issuer = context["issuer"]

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "issuer": issuer,
                    "authorization_endpoint": f"{issuer}/authorize",
                    "token_endpoint": f"{issuer}/token",
                    "jwks_uri": f"{issuer}/jwks",
                },
            )
        if request.url.path == "/jwks":
            return httpx.Response(200, json=keys.jwks())
        return httpx.Response(404)

    client = OidcClient(
        OidcProviderSettings(
            id="vectors",
            name="Vectors",
            issuer=issuer,
            client_id=context["client_id"],
            id_token_max_age_seconds=context["max_age_seconds"],
        ),
        redirect_uri="https://api.vectors.test/v1/auth/oidc/vectors/callback",
        transport=httpx.MockTransport(handle),
    )
    try:
        client.verify(build_token(vector, keys, context), nonce=context["nonce"])
    except OidcLoginError:
        return "reject"
    finally:
        client.close()
    return "accept"


# MUP-ONA T-VEC-2
def test_the_jwt_context_matches_axentra() -> None:
    from axentra.identity import oidc

    assert CORPUS["jwt_context"]["leeway_seconds"] == oidc.LEEWAY_SECONDS


# MUP-ONA T-VEC-2
@pytest.mark.parametrize("vector", _vectors("jwt"))
def test_jwt_vector(vector: dict[str, Any], keys: Keys) -> None:
    assert axentra_jwt(vector, keys) == _expected("jwt", vector)


# ---- redaction -----------------------------------------------------------------------------------------------------


# MUP-ONA T-VEC-2
@pytest.mark.parametrize("vector", _vectors("redaction"))
def test_redaction_vector(vector: dict[str, Any]) -> None:
    out = redact(vector["input"])
    text = out if isinstance(out, str) else json.dumps(out, ensure_ascii=False)
    left = [secret for secret in vector["must_not_contain"] if secret in text]
    if ("redaction", vector["id"]) in DIFFERENCES:
        assert left, f"{vector['id']} is redacted now: remove its known_differences entry for {PLATFORM}"
    else:
        assert left == [], text
