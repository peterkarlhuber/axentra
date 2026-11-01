"""The outbox dispatcher: claims due messages, delivers them, retries with exponential backoff.

Guarantees (see docs/modules/NOTIFY.md):

- Claiming uses ``FOR UPDATE SKIP LOCKED`` and moves each message to ``sending`` with a lease and a
  per-claim token in one statement, so concurrent dispatchers never claim the same message.
- Results are written only while the claim token still matches; a dispatcher whose lease expired
  cannot overwrite the outcome of the dispatcher that took over.
- Delivery is **at-least-once**: if a process dies after the provider accepted a message but
  before ``sent`` was committed, the lease expires and the message is sent again.

:meth:`NotifyDispatcher.run_once` is a plain callable, so a job worker (or cron, or
``axentra notify-dispatch``) can drive it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
import logging
import random
import threading
import time
from typing import TYPE_CHECKING, Any

from axentra.config.secrets import SecretBox
from axentra.config.settings import NotifySettings
from axentra.core.ids import new_token
from axentra.core.redaction import redact_text
from axentra.data.database import Database, DbScope, Row
from axentra.notify.providers import NotificationProvider, OutgoingMessage, ProviderError, sender_address

if TYPE_CHECKING:
    from axentra.observability.metrics import MetricsRegistry

logger = logging.getLogger(__name__)
_CTX = "axentra_notify_messages"


@dataclass
class DispatchResult:
    claimed: int = 0
    sent: int = 0
    retried: int = 0
    failed: int = 0
    lost: int = 0
    """Outcomes not recorded because the lease had expired and another dispatcher took over."""
    message_ids: list[str] = field(default_factory=list)


class NotifyDispatcher:
    def __init__(
        self,
        db: Database,
        secrets: SecretBox,
        provider: NotificationProvider,
        settings: NotifySettings,
        *,
        metrics: MetricsRegistry | None = None,
        jitter: float = 0.2,
        rng: Callable[[], float] = random.random,
    ) -> None:
        self.db = db
        self.secrets = secrets
        self.provider = provider
        self.settings = settings
        self.jitter = jitter
        self._rng = rng
        self._sender = sender_address(settings)
        self._outcomes = (
            metrics.counter(
                "axentra_notify_deliveries_total",
                "Notification delivery attempts by outcome",
                ("provider", "outcome"),
            )
            if metrics
            else None
        )
        self._duration = (
            metrics.histogram(
                "axentra_notify_send_duration_seconds",
                "Time spent in the notification provider",
                ("provider",),
            )
            if metrics
            else None
        )

    def backoff_seconds(self, attempts: int) -> float:
        """Delay before attempt ``attempts + 1``: base * 2^(attempts-1), capped, plus jitter."""
        s = self.settings
        delay = min(s.backoff_base_seconds * (2 ** max(attempts - 1, 0)), s.backoff_max_seconds)
        return float(delay * (1 + self.jitter * self._rng()))

    def _expire_exhausted(self) -> int:
        with self.db.transaction(DbScope.platform()) as tx:
            return tx.execute(
                "UPDATE axentra_notify_messages SET status = 'failed', lease_until = NULL, claim_token = NULL,"
                " last_error = coalesce(last_error, 'lease expired during the last attempt'), updated_at = now()"
                " WHERE status = 'sending' AND lease_until < now() AND attempts >= max_attempts"
            )

    def _claim(self, batch: int, token: str) -> list[Row]:
        with self.db.transaction(DbScope.platform()) as tx:
            return tx.all(
                "UPDATE axentra_notify_messages SET status = 'sending', attempts = attempts + 1,"
                " lease_until = now() + make_interval(secs => %s), claim_token = %s, updated_at = now()"
                " WHERE id IN (SELECT id FROM axentra_notify_messages WHERE"
                "   (status = 'queued' AND next_attempt_at <= now())"
                "   OR (status = 'sending' AND lease_until < now() AND attempts < max_attempts)"
                "   ORDER BY next_attempt_at, id LIMIT %s FOR UPDATE SKIP LOCKED)"
                " RETURNING *",
                (self.settings.lease_seconds, token, batch),
            )

    def _outgoing(self, row: Row) -> OutgoingMessage:
        mid = row["id"]
        if row["subject_enc"] is None or row["body_text_enc"] is None:
            raise ProviderError("the message content is no longer available", permanent=True)
        try:
            subject = self.secrets.decrypt(row["subject_enc"], f"{_CTX}|{mid}|subject")
            text = self.secrets.decrypt(row["body_text_enc"], f"{_CTX}|{mid}|text")
            html = (
                self.secrets.decrypt(row["body_html_enc"], f"{_CTX}|{mid}|html")
                if row["body_html_enc"]
                else None
            )
        except Exception:
            raise ProviderError("the message content cannot be decrypted", permanent=True) from None
        return OutgoingMessage(
            message_id=mid,
            product_id=row["product_id"],
            tenant_id=row["tenant_id"],
            channel=row["channel"],
            sender=self._sender,
            recipient=row["recipient"],
            subject=subject,
            text=text,
            html=html,
        )

    def _count(self, outcome: str) -> None:
        if self._outcomes is not None:
            self._outcomes.inc(provider=self.provider.name, outcome=outcome)

    def _deliver(self, row: Row, token: str, result: DispatchResult) -> None:
        mid = row["id"]
        started = time.perf_counter()
        try:
            outgoing = self._outgoing(row)
            provider_id = self.provider.send(outgoing)
            error: ProviderError | None = None
        except ProviderError as exc:
            error = exc
        except Exception as exc:
            error = ProviderError(f"{type(exc).__name__}: {exc}")
        finally:
            if self._duration is not None:
                self._duration.observe(time.perf_counter() - started, provider=self.provider.name)
        with self.db.transaction(DbScope.platform()) as tx:
            if error is None:
                n = tx.execute(
                    "UPDATE axentra_notify_messages SET status = 'sent', sent_at = now(), provider = %s,"
                    " provider_message_id = %s, last_error = NULL, lease_until = NULL, claim_token = NULL,"
                    " updated_at = now(),"
                    " subject_enc = CASE WHEN sensitive THEN NULL ELSE subject_enc END,"
                    " body_text_enc = CASE WHEN sensitive THEN NULL ELSE body_text_enc END,"
                    " body_html_enc = CASE WHEN sensitive THEN NULL ELSE body_html_enc END,"
                    " content_purged_at = CASE WHEN sensitive THEN now() ELSE content_purged_at END"
                    " WHERE id = %s AND claim_token = %s",
                    (self.provider.name, str(provider_id)[:500], mid, token),
                )
                outcome = "sent"
            else:
                message = redact_text(str(error))[:500]
                final = error.permanent or row["attempts"] >= row["max_attempts"]
                if final:
                    n = tx.execute(
                        "UPDATE axentra_notify_messages SET status = 'failed', provider = %s, last_error = %s,"
                        " lease_until = NULL, claim_token = NULL, updated_at = now()"
                        " WHERE id = %s AND claim_token = %s",
                        (self.provider.name, message, mid, token),
                    )
                    outcome = "failed"
                else:
                    n = tx.execute(
                        "UPDATE axentra_notify_messages SET status = 'queued', provider = %s, last_error = %s,"
                        " next_attempt_at = now() + make_interval(secs => %s), lease_until = NULL,"
                        " claim_token = NULL, updated_at = now() WHERE id = %s AND claim_token = %s",
                        (self.provider.name, message, self.backoff_seconds(row["attempts"]), mid, token),
                    )
                    outcome = "retried"
        if n == 0:
            logger.warning("notification %s: lease lost before the outcome was recorded", mid)
            result.lost += 1
            self._count("lease_lost")
            return
        setattr(result, outcome, getattr(result, outcome) + 1)
        self._count(outcome)
        if error is not None:
            logger.info("notification %s attempt %s %s", mid, row["attempts"], outcome)

    def run_once(self, batch: int = 20) -> DispatchResult:
        """Claim up to ``batch`` due messages and deliver them; returns what happened."""
        if batch < 1:
            raise ValueError("batch must be positive")
        result = DispatchResult()
        exhausted = self._expire_exhausted()
        result.failed += exhausted
        token = new_token(12)
        rows = self._claim(batch, token)
        result.claimed = len(rows)
        for row in rows:
            result.message_ids.append(row["id"])
            self._deliver(row, token, result)
        return result

    def run_loop(
        self,
        *,
        batch: int = 20,
        interval: float = 2.0,
        stop: threading.Event | None = None,
        on_result: Callable[[DispatchResult], Any] | None = None,
    ) -> None:
        """Dispatch until ``stop`` is set; sleeps ``interval`` seconds when there was nothing to do."""
        stop = stop or threading.Event()
        while not stop.is_set():
            try:
                res = self.run_once(batch)
                if on_result is not None:
                    on_result(res)
                idle = res.claimed == 0
            except Exception:
                logger.exception("notify dispatcher iteration failed")
                idle = True
            if idle:
                stop.wait(interval)
