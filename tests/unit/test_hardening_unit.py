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
