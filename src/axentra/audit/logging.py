"""Structured JSON logging with request correlation and secret redaction."""

from __future__ import annotations

from contextvars import ContextVar
from datetime import UTC, datetime
import json
import logging
from typing import Any

from axentra.core.db_errors import DbErrorRedactionFilter
from axentra.core.redaction import redact_auth_query, redact_text

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
            # ``exc_text`` first: DbErrorRedactionFilter stores the traceback without database values there.
            data["exc"] = redact_text(record.exc_text or self.formatException(record.exc_info))
        keys = ("method", "path", "status", "duration_ms", "product_id", "tenant_id", "job_id")
        for key in (*keys, "db_sqlstate", "db_constraint"):
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
    # Every record this handler emits loses the values database errors carry (B-06-1).
    handler.addFilter(DbErrorRedactionFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    install_access_log_redaction()
    install_db_error_redaction()


class RedactAuthQuery(logging.Filter):
    """Apply :func:`redact_auth_query` to log records (uvicorn's access log prints the full request
    line, and its formatter does not go through :class:`JsonFormatter`)."""

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


#: Loggers that log database errors raised while answering a request, also through handlers that
#: :func:`configure_logging` did not install: Axentra's error handlers (``axentra.http``) and uvicorn's
#: "Exception in ASGI application" (``uvicorn.error``, which has its own handler and does not propagate).
DB_ERROR_LOGGERS = ("axentra.http", "uvicorn.error")


def install_db_error_redaction() -> None:
    """Install :class:`~axentra.core.db_errors.DbErrorRedactionFilter` on :data:`DB_ERROR_LOGGERS` (B-06-1,
    TABRION MIG-AXE-0); installing twice is harmless. uvicorn's logging configuration keeps logger filters."""
    for name in DB_ERROR_LOGGERS:
        log = logging.getLogger(name)
        if not any(isinstance(f, DbErrorRedactionFilter) for f in log.filters):
            log.addFilter(DbErrorRedactionFilter())
