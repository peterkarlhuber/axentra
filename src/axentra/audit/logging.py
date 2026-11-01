"""Structured JSON logging with request correlation and secret redaction."""

from __future__ import annotations

from contextvars import ContextVar
from datetime import UTC, datetime
import json
import logging
import re
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
    install_access_log_redaction()


# Adapted from peterkarlhuber/nodestro-api src/nodestro_api/identity.py at e7fb1dba1f5521d13ab2d90ac41e101f2c6f5bea (MIT, Copyright (c) 2026 Peter Karlhuber)
#: Query values that are login secrets: OIDC ``code`` and ``state``, tokens, setup and invitation links.
_AUTH_QUERY = re.compile(r"(?i)([?&](?:code|state|[a-z_]*token|setup|invitation)=)[^&\s\"']*")


def redact_auth_query(text: str) -> str:
    return _AUTH_QUERY.sub(r"\1[redacted]", text) if "=" in text else text


class RedactAuthQuery(logging.Filter):
    """Replace the values of ``code``, ``state``, ``*token``, ``setup`` and ``invitation`` query
    parameters in log records (uvicorn's access log prints the full request line)."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            # uvicorn's AccessFormatter unpacks the arguments: keep them, redacted.
            record.args = tuple(redact_auth_query(a) if isinstance(a, str) else a for a in record.args)
        if isinstance(record.msg, str):
            record.msg = redact_auth_query(record.msg)
        return True


def install_access_log_redaction() -> None:
    """Install :class:`RedactAuthQuery` on ``uvicorn.access``; installing twice is harmless."""
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, RedactAuthQuery) for f in access.filters):
        access.addFilter(RedactAuthQuery())
