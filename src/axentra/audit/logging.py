"""Structured JSON logging with request correlation and secret redaction."""

from __future__ import annotations

from contextvars import ContextVar
from datetime import UTC, datetime
import json
import logging
from typing import Any

from axentra.core.redaction import redact_text

request_id_var: ContextVar[str | None] = ContextVar("axentra_request_id", default=None)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        rid = request_id_var.get()
        if rid:
            data["request_id"] = rid
        if record.exc_info:
            data["exc"] = redact_text(self.formatException(record.exc_info))
        for key in ("method", "path", "status", "duration_ms", "product_id", "tenant_id", "job_id"):
            if hasattr(record, key):
                data[key] = getattr(record, key)
        return json.dumps(data, default=str)


class RedactingTextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact_text(super().format(record))


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        JsonFormatter()
        if fmt == "json"
        else RedactingTextFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
