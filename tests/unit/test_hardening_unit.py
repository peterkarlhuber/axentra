"""Hardening units: API docs defaults, token buckets, package exports."""

from __future__ import annotations

from pathlib import Path
import re

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


COMPOSE_DIR = Path(__file__).resolve().parents[2] / "deploy" / "compose"


@pytest.mark.parametrize("name", ["single", "multi", "taskboard"])
def test_compose_publishes_on_loopback_by_default(name: str) -> None:
    """C-03: a quick start never publishes the API on every host interface."""
    text = (COMPOSE_DIR / f"docker-compose.{name}.yml").read_text(encoding="utf-8")
    ports = re.findall(r'^\s+- "([^"]*:\d+)"\s*$', text, re.MULTILINE)
    assert ports
    assert all(p.startswith("${AXENTRA_BIND_ADDRESS:-127.0.0.1}:") for p in ports), ports


def _env_template(name: str) -> dict[str, str]:
    lines = (COMPOSE_DIR / name).read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines if line and not line.startswith("#"))


def test_compose_env_templates() -> None:
    trial = _env_template(".env.example")
    assert trial["AXENTRA_ENVIRONMENT"] == "development" and trial["AXENTRA_BIND_ADDRESS"] == "127.0.0.1"
    assert "LOCAL TRIAL" in (COMPOSE_DIR / ".env.example").read_text(encoding="utf-8")
    production = _env_template(".env.production.example")
    assert production["AXENTRA_ENVIRONMENT"] == "production"
    assert production["AXENTRA_PUBLIC_URL"].startswith("https://")
    assert production["AXENTRA_BIND_ADDRESS"] == "127.0.0.1"
    assert set(trial) - {"TASKBOARD_ORIGIN", "TASKBOARD_HTTP_PORT"} == set(production)


@pytest.mark.parametrize("password", ["change-me-app", "change-me-owner", "CHANGE-ME", "replace-with-x"])
def test_placeholder_database_password_is_refused_in_production(password: str, caplog) -> None:  # type: ignore[no-untyped-def]
    """C-03: the template passwords of .env.example never reach a production database connection."""
    from axentra.core.errors import ConfigurationError
    from axentra.platform import _database_url, _migration_url

    url = f"postgresql://axentra_app:{password}@db:5432/axentra"
    environ = {"AXENTRA__DATABASE__URL": url, "AXENTRA__SECURITY__PUBLIC_URL": "https://api.example.com"}
    production = load_settings(None, environ={**environ, "AXENTRA__ENVIRONMENT": "production"})
    with pytest.raises(ConfigurationError, match="placeholder password"):
        _database_url(production)
    with pytest.raises(ConfigurationError, match="placeholder password"):
        _migration_url(production)
    development = load_settings(None, environ={**environ, "AXENTRA__ENVIRONMENT": "development"})
    assert _database_url(development) == url
    assert "placeholder password" in caplog.text
    ok = load_settings(
        None,
        environ={
            **environ,
            "AXENTRA__ENVIRONMENT": "production",
            "AXENTRA__DATABASE__URL": url.replace(password, "9f3a1c"),
        },
    )
    assert _database_url(ok).endswith("@db:5432/axentra")
