"""Optional OpenTelemetry tracing.

Enabled only when ``observability.otel_enabled = true`` **and** the ``otel`` extra is installed
(``pip install axentra[otel]``). Otherwise :func:`setup_tracing` returns a :class:`NoopTracing`
whose spans do nothing, so callers never branch and importing this module never needs the SDK.

The tracer provider is private to the Axentra instance (the global OpenTelemetry provider is not
replaced), spans are exported with OTLP/HTTP through a batch processor.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import logging
from typing import Any

from axentra.config.settings import ObservabilitySettings
from axentra.core.db_errors import redacted_traceback, safe_error_text

logger = logging.getLogger(__name__)


class _NoopSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def record_exception(self, exc: BaseException) -> None:
        pass

    def set_status_error(self, description: str = "") -> None:
        pass


class NoopTracing:
    enabled = False

    @contextmanager
    def span(self, name: str, attributes: dict[str, Any] | None = None) -> Iterator[Any]:
        yield _NoopSpan()

    def shutdown(self) -> None:
        pass


class OtelTracing:
    enabled = True

    def __init__(self, provider: Any) -> None:
        self.provider = provider
        self.tracer = provider.get_tracer("axentra")

    @contextmanager
    def span(self, name: str, attributes: dict[str, Any] | None = None) -> Iterator[Any]:
        # OpenTelemetry would record ``str(exc)`` and the raw traceback as the span's exception event and status,
        # and export them: for a database error that is the DETAIL text with row values (B-06-1). The exception
        # is recorded here instead, without those values.
        with self.tracer.start_as_current_span(
            name, attributes=attributes or {}, record_exception=False, set_status_on_exception=False
        ) as span:
            try:
                yield span
            except BaseException as exc:
                if not isinstance(exc, GeneratorExit):
                    record_redacted_exception(span, exc)
                raise

    def shutdown(self) -> None:
        try:
            self.provider.shutdown()
        except Exception:
            logger.warning("tracing shutdown failed", exc_info=True)


Tracing = NoopTracing | OtelTracing


def record_redacted_exception(span: Any, exc: BaseException) -> None:
    """Record ``exc`` on an OpenTelemetry span as the SDK does (``exception`` event, ``ERROR`` status), with a
    message and stack trace that carry no database values (:func:`~axentra.core.db_errors.safe_error_text`)."""
    from opentelemetry.trace import Status, StatusCode

    message = safe_error_text(exc)
    span.record_exception(
        exc,
        attributes={
            "exception.message": message,
            "exception.stacktrace": redacted_traceback(exc),
        },
        escaped=True,
    )
    span.set_status(Status(StatusCode.ERROR, f"{type(exc).__name__}: {message}"))


def setup_tracing(settings: ObservabilitySettings, *, span_processor: Any = None) -> Tracing:
    """Build the tracing facade; ``span_processor`` replaces the OTLP exporter (tests)."""
    if not settings.otel_enabled:
        return NoopTracing()
    try:
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        logger.warning(
            "observability.otel_enabled is set but the 'otel' extra is not installed; tracing is off"
        )
        return NoopTracing()
    if span_processor is None:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        except ImportError:
            logger.warning("the OTLP/HTTP exporter is not installed; tracing is off")
            return NoopTracing()
        exporter = (
            OTLPSpanExporter(endpoint=settings.otel_endpoint)
            if settings.otel_endpoint
            else OTLPSpanExporter()
        )
        span_processor = BatchSpanProcessor(exporter)
    provider = TracerProvider(resource=Resource.create({"service.name": settings.otel_service_name}))
    provider.add_span_processor(span_processor)
    return OtelTracing(provider)
