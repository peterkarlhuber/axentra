"""Periodic maintenance: retention and expiry purges (``axentra maintenance purge``).

Runs, in order: audit retention (``observability.audit_retention_days``), expired sessions/login
states/setup tokens, notification retention (if the notify module is enabled), and every callable
registered in ``ax.maintenance_hooks`` (``name -> callable() -> int | dict``) by other modules.
Each task runs independently; a failing task is reported and does not stop the others.
"""

from __future__ import annotations

from collections.abc import Callable
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from axentra.platform import Axentra

logger = logging.getLogger(__name__)


def run_maintenance(ax: Axentra) -> dict[str, Any]:
    tasks: dict[str, Callable[[], Any]] = {
        "audit_events_deleted": lambda: ax.audit.purge(ax.settings.observability.audit_retention_days),
        "sessions_deleted": ax.identity.purge_expired,
    }
    notify = getattr(ax, "notify", None)
    if notify is not None:
        tasks["notify"] = notify.purge_retention
    tasks.update(getattr(ax, "maintenance_hooks", {}) or {})
    report: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for name, fn in tasks.items():
        try:
            report[name] = fn()
        except Exception as exc:
            logger.exception("maintenance task %s failed", name)
            errors[name] = type(exc).__name__
    if errors:
        report["errors"] = errors
    return report
