from __future__ import annotations

from datetime import UTC, datetime
import random

import pytest

from axentra.config.settings import EventsSettings, load_settings
from axentra.core.errors import ConfigurationError, ValidationFailed
from axentra.events.cron import CronExpr, next_interval_slot
from axentra.events.http_client import TargetRefused, parse_target
from axentra.events.jobs import backoff_delay, check_kind, format_error
from axentra.events.streams import parse_position
from axentra.events.webhooks import sign, signature_header, verify_signature


def _t(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=UTC)


@pytest.mark.parametrize(
    ("expr", "after", "expected"),
    [
        ("* * * * *", "2026-01-01T10:00:30", "2026-01-01T10:01:00"),
        ("*/15 * * * *", "2026-01-01T10:01:00", "2026-01-01T10:15:00"),
        ("0 3 * * *", "2026-01-01T03:00:00", "2026-01-02T03:00:00"),
        ("30 9 1 * *", "2026-01-15T00:00:00", "2026-02-01T09:30:00"),
        ("0 0 * * 0", "2026-01-01T00:00:00", "2026-01-04T00:00:00"),  # Sunday
        ("0 0 * * 7", "2026-01-01T00:00:00", "2026-01-04T00:00:00"),
        ("0 12 13 * 5", "2026-01-01T00:00:00", "2026-01-02T12:00:00"),  # dom OR dow (Friday)
        ("0 0 29 2 *", "2026-03-01T00:00:00", "2028-02-29T00:00:00"),
        ("5-10/5 1,2 * 6-7 1-5", "2026-06-01T01:07:00", "2026-06-01T01:10:00"),
    ],
)
def test_cron_next(expr, after, expected):
    assert CronExpr.parse(expr).next_after(_t(after)) == _t(expected)


@pytest.mark.parametrize(
    "bad", ["* * * *", "60 * * * *", "* 24 * * *", "a * * * *", "5-1 * * * *", "*/0 * * * *", "1,,2 * * * *"]
)
def test_cron_invalid(bad):
    with pytest.raises(ValidationFailed):
        CronExpr.parse(bad)


def test_cron_never_matching():
    with pytest.raises(ValidationFailed):
        CronExpr.parse("0 0 31 2 *").next_after(_t("2026-01-01T00:00:00"))


def test_interval_slots_are_aligned():
    assert next_interval_slot(_t("2026-01-01T10:00:59"), 60) == _t("2026-01-01T10:01:00")
    assert next_interval_slot(_t("2026-01-01T10:01:00"), 60) == _t("2026-01-01T10:02:00")


def test_backoff_is_exponential_jittered_and_capped():
    rng = random.Random(1)
    for attempt in range(1, 8):
        d = backoff_delay(attempt, 2, 30, rng=rng)
        step = min(30, 2 * 2 ** (attempt - 1))
        assert step / 2 <= d <= step
    assert backoff_delay(500, 2, 30) <= 30


def test_kind_and_error_formatting():
    check_kind("billing.invoice:send")
    with pytest.raises(ValidationFailed):
        check_kind("Bad")
    msg = format_error(RuntimeError("failed with axk_abc123_" + "A" * 30))
    assert "AAAAAAAAAA" not in msg and msg.startswith("RuntimeError")


def test_signature_roundtrip_and_tolerance():
    body = b'{"a":1}'
    hdr = signature_header(["whsec_a", "whsec_old"], 1_700_000_000, body)
    assert hdr.startswith("t=1700000000,v1=") and hdr.count("v1=") == 2
    assert verify_signature("whsec_a", hdr, body, now=1_700_000_100)
    assert verify_signature("whsec_old", hdr, body, now=1_700_000_100)
    assert not verify_signature("whsec_a", hdr, b'{"a":2}', now=1_700_000_100)
    assert not verify_signature("whsec_a", hdr, body, now=1_700_001_000)
    assert not verify_signature("whsec_a", "garbage", body)
    import hashlib
    import hmac

    assert sign("k", 5, b"x") == hmac.new(b"k", b"5.x", hashlib.sha256).hexdigest()


def test_parse_target_rules():
    s = EventsSettings()
    assert parse_target("https://example.com/h?a=1", s, production=True).path == "/h?a=1"
    for bad in (
        "http://example.com/",
        "https://127.0.0.1/",
        "https://10.1.2.3/",
        "https://[fe80::1]/",
        "https://0.0.0.0/",
        "https://svc.internal/",
        "https://a@example.com/",
        "https:///x",
    ):
        with pytest.raises(TargetRefused):
            parse_target(bad, s, production=False)
    allowed = EventsSettings(webhook_allow_http=True, webhook_allow_private_targets=True)
    assert parse_target("http://127.0.0.1:9/", allowed, production=False).port == 9
    with pytest.raises(TargetRefused):
        parse_target("http://127.0.0.1:9/", allowed, production=True)


def test_production_refuses_http_webhooks():
    with pytest.raises(ConfigurationError, match="webhook_allow_http"):
        load_settings(
            None,
            environ={},
            environment="production",
            security={"public_url": "https://api.example.com", "master_keys_ref": "env:X"},
            events={"webhook_allow_http": True},
        ).validate_security()


def test_stream_positions():
    assert parse_position("42") == 42
    for bad in ("", "-1", "1-2", "x", "9" * 30):
        with pytest.raises(ValidationFailed):
            parse_position(bad)
