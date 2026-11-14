"""Hardening units: API docs defaults, token buckets, package exports."""

from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from axentra.api.app import create_app, iter_api_routes
from axentra.api.limits import TokenBuckets
from axentra.config.secrets import generate_key
from axentra.config.settings import load_settings


def _paths(app):  # type: ignore[no-untyped-def]
    return {p for p, _, _ in iter_api_routes(list(app.routes))}


def test_api_docs_public_outside_production():
    app = create_app(load_settings(None, environ={}, environment="test", mode="multi"), start=False)
    client = TestClient(app)
    r = client.get("/v1/openapi.json")
    assert r.status_code == 200 and "/v1/products" in r.json()["paths"]
    assert client.get("/v1/docs").status_code == 200
    assert "/v1/docs" in _paths(app)


@pytest.mark.parametrize("override", [None, "disabled"])
def test_api_docs_disabled_in_production_by_default(tmp_path, override):
    keyfile = tmp_path / "keys"
    keyfile.write_text(f"p1:{generate_key()}", encoding="utf-8")
    security = {"public_url": "https://api.example.com", "master_keys_ref": f"file:{keyfile}"}
    if override:
        security["api_docs"] = override
    settings = load_settings(None, environ={}, environment="production", mode="multi", security=security)
    assert settings.api_docs_mode == "disabled"
    app = create_app(settings, start=False)
    assert {"/v1/docs", "/v1/openapi.json"}.isdisjoint(_paths(app))
    assert TestClient(app).get("/v1/openapi.json").status_code == 404
    # The contract can still be exported (axentra openapi export uses app.openapi()).
    assert "/v1/products" in app.openapi()["paths"]


def test_api_docs_explicitly_public_in_production(tmp_path):
    keyfile = tmp_path / "keys"
    keyfile.write_text(f"p1:{generate_key()}", encoding="utf-8")
    security = {"public_url": "https://x.example", "master_keys_ref": f"file:{keyfile}", "api_docs": "public"}
    settings = load_settings(None, environ={}, environment="production", mode="multi", security=security)
    assert "/v1/openapi.json" in _paths(create_app(settings, start=False))


def test_token_bucket_refills_and_bounds_keys():
    b = TokenBuckets(per_minute=60, burst=2, max_keys=3)
    assert b.take("a", now=0.0) == 0 and b.take("a", now=0.0) == 0
    assert b.take("a", now=0.0) == pytest.approx(1.0)
    assert b.take("a", now=1.0) == 0  # one token per second
    for key in "bcd":
        b.take(key, now=1.0)
    assert len(b._buckets) == 3 and "a" not in b._buckets


def test_load_settings_is_exported_from_the_package():
    import axentra

    assert axentra.load_settings is load_settings
    assert axentra.Settings.__name__ == "Settings"
    with pytest.raises(AttributeError):
        axentra.nope  # noqa: B018


BAD_EMAILS = [
    "victim@x.test\r\nBcc:evil@evil.test",
    "victim@x.test\nBcc:evil@evil.test",
    "a@x.test,b@evil.test",
    "a@x.test;b@evil.test",
    "Name <a@x.test>",
    '"a"@x.test',
    "a(comment)@x.test",
    "a\tb@x.test",
    "a b@x.test",
    "a\x00@x.test",
    "a\u2028@x.test",
    "a\u200b@x.test",
]


@pytest.mark.parametrize("email", BAD_EMAILS)
def test_normalize_email_refuses_header_separators_and_control_characters(email: str) -> None:
    """B-05: such an address was stored, but no mail could ever be sent to it."""
    from axentra.core.errors import ValidationFailed
    from axentra.identity.service import normalize_email

    with pytest.raises(ValidationFailed):
        normalize_email(email)


@pytest.mark.parametrize(
    ("email", "normalized"),
    [
        (" Ops@Example.COM ", "Ops@example.com"),
        ("o'brien+tag@x.test", "o'brien+tag@x.test"),
        ("jörg@bücher.de", "jörg@bücher.de"),
    ],
)
def test_normalize_email_keeps_ordinary_addresses(email: str, normalized: str) -> None:
    from axentra.identity.service import normalize_email

    assert normalize_email(email) == normalized


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080", "http://api.localhost"]
)
def test_unset_environment_is_fine_for_a_local_trial(url: str) -> None:
    settings = load_settings(None, environ={"AXENTRA__SECURITY__PUBLIC_URL": url})
    assert settings.environment == "development"
    settings.validate_security()


@pytest.mark.parametrize("url", ["https://api.example.com", "http://10.0.0.5:8080", "http://0.0.0.0:8080"])
def test_unset_environment_with_a_reachable_public_url_refuses_to_start(url: str) -> None:
    """B-03: a forgotten ``environment`` no longer silently runs a reachable installation in development mode."""
    from axentra.core.errors import ConfigurationError

    with pytest.raises(ConfigurationError, match="environment is not set"):
        load_settings(None, environ={"AXENTRA__SECURITY__PUBLIC_URL": url}).validate_security()
    # Set explicitly, development stays possible (for example a trial on a LAN host).
    load_settings(
        None, environ={"AXENTRA__SECURITY__PUBLIC_URL": url, "AXENTRA__ENVIRONMENT": "development"}
    ).validate_security()
