from __future__ import annotations

import pytest

from axentra.api.app import create_app
from axentra.config.settings import Environment
from tests.integration.conftest import Browser


def test_metrics_endpoint_open_outside_production(world):
    world.admin.get("/v1/products")
    world.browser().get("/v1/products")  # 401
    r = world.browser().client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain; version=0.0.4")
    text = r.text
    assert 'axentra_http_requests_total{method="GET",route="/v1/products",status="200"}' in text
    assert 'axentra_http_requests_total{method="GET",route="/v1/products",status="401"}' in text
    assert 'axentra_auth_failures_total{reason="unauthenticated"}' in text
    assert "axentra_http_request_duration_seconds_bucket" in text
    assert "axentra_db_pool_size" in text and "axentra_db_pool_max 6" in text
    # Raw paths with ids never become label values.
    world.admin.get("/v1/products/prd_01doesnotexist0000000000000")
    assert "prd_01doesnotexist" not in world.browser().client.get("/metrics").text
    assert 'route="/v1/products/{product_id}"' in world.browser().client.get("/metrics").text


def test_metrics_token_protection(ax_factory, monkeypatch):
    monkeypatch.setenv("AXENTRA_TEST_METRICS_TOKEN", "metrics-token-123")
    ax = ax_factory(observability={"metrics_token_ref": "env:AXENTRA_TEST_METRICS_TOKEN"})
    c = Browser(create_app(axentra=ax, start=False)).client
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    r = c.get("/metrics", headers={"Authorization": "Bearer metrics-token-123"})
    assert r.status_code == 200 and 'axentra_auth_failures_total{reason="metrics_token"} 2' in r.text
    # Production keeps working with a token ...
    ax.settings.environment = Environment.PRODUCTION
    assert c.get("/metrics", headers={"Authorization": "Bearer metrics-token-123"}).status_code == 200


def test_metrics_disabled_in_production_without_token_or_when_off(ax_factory):
    ax = ax_factory()
    c = Browser(create_app(axentra=ax, start=False)).client
    ax.settings.environment = Environment.PRODUCTION
    assert c.get("/metrics").status_code == 404
    ax2 = ax_factory(observability={"metrics_enabled": False})
    assert Browser(create_app(axentra=ax2, start=False)).client.get("/metrics").status_code == 404


def test_readiness_reports_notify_provider(world, ax_factory):
    r = world.browser().client.get("/v1/health/ready")
    assert r.status_code == 200 and r.json()["checks"] == {"database": True, "notify_provider": True}
    bad = ax_factory(
        notify={"provider": "smtp", "smtp_username": "u", "smtp_password_ref": "env:AXENTRA_NOPE_UNSET"}
    )
    r = Browser(create_app(axentra=bad, start=False)).client.get("/v1/health/ready")
    assert r.status_code == 503 and r.json()["checks"]["notify_provider"] is False


def test_tracing_middleware_records_request_spans(ax_factory):
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from axentra.observability.tracing import setup_tracing

    ax = ax_factory(observability={"otel_enabled": True})
    exporter = InMemorySpanExporter()
    ax.tracing = setup_tracing(ax.settings.observability, span_processor=SimpleSpanProcessor(exporter))
    c = Browser(create_app(axentra=ax, start=False)).client
    r = c.get("/v1/products/prd_x", headers={"X-Request-ID": "trace-test-1"})
    assert r.status_code == 401
    (span,) = exporter.get_finished_spans()
    assert span.name == "GET /v1/products/{product_id}"
    assert span.attributes["http.route"] == "/v1/products/{product_id}"
    assert span.attributes["http.response.status_code"] == 401
    assert span.attributes["axentra.request_id"] == "trace-test-1"
