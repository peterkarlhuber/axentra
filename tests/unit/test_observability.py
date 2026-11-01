from __future__ import annotations

import subprocess
import sys

import pytest

from axentra.config.settings import ObservabilitySettings
from axentra.observability.metrics import MAX_SERIES, MetricsRegistry
from axentra.observability.tracing import NoopTracing, setup_tracing


class _Route:
    path = "/v1/products/{product_id}"


def test_registry_renders_prometheus_text():
    reg = MetricsRegistry()
    reg.observe_request("GET", _Route(), 200, 12.5)
    reg.observe_request("get", None, 401, 1.0)
    reg.observe_request("BREW", _Route(), 403, 1.0)
    c = reg.counter("demo_total", 'Help with "quotes"\nand newline', ("kind",))
    c.inc(kind='a"b\\c')
    assert reg.counter("demo_total", "again", ("kind",)) is c
    with pytest.raises(ValueError):
        reg.histogram("demo_total", "x")
    with pytest.raises(ValueError):
        c.inc(other="x")
    text = reg.render()
    assert (
        'axentra_http_requests_total{method="GET",route="/v1/products/{product_id}",status="200"} 1' in text
    )
    assert 'axentra_http_requests_total{method="GET",route="unmatched",status="401"} 1' in text
    assert 'method="OTHER"' in text
    assert 'axentra_auth_failures_total{reason="unauthenticated"} 1' in text
    assert 'axentra_auth_failures_total{reason="forbidden"} 1' in text
    assert (
        'axentra_http_request_duration_seconds_bucket{method="GET",route="/v1/products/{product_id}",le="0.025"} 1'
        in text
    )
    assert 'le="+Inf"' in text and "axentra_http_request_duration_seconds_count" in text
    assert 'demo_total{kind="a\\"b\\\\c"} 1' in text
    assert '# HELP demo_total Help with "quotes"\\nand newline' in text
    assert "# TYPE demo_total counter" in text


def test_cardinality_is_bounded():
    reg = MetricsRegistry()
    c = reg.counter("many_total", "x", ("id",))
    for i in range(MAX_SERIES + 50):
        c.inc(id=str(i))
    assert c.value(id="other") == 50
    assert reg.render().count("many_total{") == MAX_SERIES + 1


def test_gauge_callbacks_and_histogram_counts():
    reg = MetricsRegistry()
    reg.gauge("demo_gauge", "x", ("pool",), callback=lambda: [({"pool": "a"}, 3)])
    h = reg.histogram("demo_seconds", "x", buckets=(0.1, 1))
    h.observe(0.05)
    h.observe(5)
    assert h.count() == 2
    text = reg.render()
    assert 'demo_gauge{pool="a"} 3' in text
    assert 'demo_seconds_bucket{le="0.1"} 1' in text and 'demo_seconds_bucket{le="+Inf"} 2' in text


def test_tracing_is_noop_when_disabled():
    t = setup_tracing(ObservabilitySettings())
    assert isinstance(t, NoopTracing) and not t.enabled
    with t.span("x", {"a": 1}) as span:
        span.set_attribute("b", 2)


def test_tracing_module_imports_without_otel():
    code = (
        "import sys\n"
        "for m in ['opentelemetry', 'opentelemetry.sdk', 'opentelemetry.sdk.trace']: sys.modules[m] = None\n"
        "from axentra.config.settings import ObservabilitySettings\n"
        "from axentra.observability.tracing import setup_tracing, NoopTracing\n"
        "t = setup_tracing(ObservabilitySettings(otel_enabled=True))\n"
        "assert isinstance(t, NoopTracing)\n"
        "import axentra.platform\n"
        "print('ok')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "ok"


def test_tracing_with_in_memory_exporter():
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    t = setup_tracing(
        ObservabilitySettings(otel_enabled=True, otel_service_name="svc"),
        span_processor=SimpleSpanProcessor(exporter),
    )
    assert t.enabled
    with t.span("work", {"k": "v"}):
        pass
    spans = exporter.get_finished_spans()
    assert [s.name for s in spans] == ["work"]
    assert spans[0].attributes["k"] == "v"
    assert spans[0].resource.attributes["service.name"] == "svc"
    t.shutdown()
