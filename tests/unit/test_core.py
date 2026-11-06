from __future__ import annotations

import base64
from datetime import UTC, datetime

import pytest

from axentra.config.secrets import Keyring, SecretBox, generate_key, resolve_secret
from axentra.config.settings import load_settings
from axentra.core.errors import ConfigurationError, InvalidCursor, ValidationFailed
from axentra.core.ids import is_id, new_id
from axentra.core.pagination import MAX_CURSOR_CHARS, clamp_limit, decode_cursor, encode_cursor
from axentra.core.redaction import REDACTED, redact, redact_text


def test_ids_are_prefixed_unique_and_sortable():
    ids = [new_id("ten") for _ in range(200)]
    assert len(set(ids)) == 200
    assert all(is_id(i, "ten") for i in ids)
    with pytest.raises(ValueError):
        new_id("BAD")


def test_cursor_roundtrip_and_validation():
    assert decode_cursor(encode_cursor(["a", 1])) == ["a", 1]
    with pytest.raises(ValidationFailed):
        decode_cursor("%%%")
    with pytest.raises(ValidationFailed):
        clamp_limit(500)


def test_cursor_shapes():
    issued = datetime(2026, 11, 2, 10, 0, 0, 123456, tzinfo=UTC)
    cursor = encode_cursor([issued.isoformat(), "msg_1"])
    assert decode_cursor(cursor, ("timestamp", "str")) == [issued, "msg_1"]
    assert decode_cursor(None, ("str",)) is None and decode_cursor("", ("str",)) is None
    # Any offset becomes UTC; "Z" is accepted.
    assert decode_cursor(encode_cursor(["2026-11-02T12:30:00+02:30", "x"]), ("timestamp", "str")) == [
        datetime(2026, 11, 2, 10, 0, tzinfo=UTC),
        "x",
    ]
    assert decode_cursor(encode_cursor(["2026-11-02T10:00:00Z", "x"]), ("timestamp", "str"))
    assert decode_cursor(encode_cursor([2**63 - 1, "x"]), ("int", "str")) == [2**63 - 1, "x"]
    for values, shape in [
        (["x"], ("timestamp", "str")),
        (["2026-11-02T10:00:00+00:00", "x", "y"], ("timestamp", "str")),
        ([True], ("int",)),
        ([1.0], ("int",)),
        ([2**63], ("int",)),
        ([1], ("str",)),
        ([""], ("str",)),
        (["a\x00b"], ("str",)),
        (["\ud800"], ("str",)),
        (["2026-W45-1T10:00:00+00:00"], ("timestamp",)),
        (["2026-11-02T10:00:00,5+00:00"], ("timestamp",)),
        (["2026-11-02T10:00:00+05:30:15.123456"], ("timestamp",)),
        (["2026-11-02T10:00:00"], ("timestamp",)),
        (["0001-01-01T00:00:00+14:00"], ("timestamp",)),
    ]:
        with pytest.raises(InvalidCursor) as ei:
            decode_cursor(encode_cursor(values), shape)
        assert (ei.value.status, ei.value.code, ei.value.detail) == (400, "invalid_cursor", "invalid cursor")
    # Without a shape: still a list of safe values only.
    for bad in (encode_cursor(["a\x00"]), encode_cursor([{"k": "\ud800"}]), "A" * (MAX_CURSOR_CHARS + 1)):
        with pytest.raises(InvalidCursor):
            decode_cursor(bad)
    # The detail never carries decoder text.
    with pytest.raises(InvalidCursor) as ei:
        decode_cursor(base64.urlsafe_b64encode(b"\xff\xfe").decode())
    assert ei.value.__cause__ is None and str(ei.value) == "invalid cursor"


def test_redaction():
    data = {"password": "x", "nested": {"api_key": "y", "ok": "fine"}, "note": "Bearer abcdefghijklmnop"}
    out = redact(data)
    assert (
        out["password"] == REDACTED and out["nested"]["api_key"] == REDACTED and out["nested"]["ok"] == "fine"
    )
    assert "abcdefghijklmnop" not in out["note"]
    assert "s3cr3t" not in redact_text("postgresql://user:s3cr3t@db:5432/x")
    key = "axk_" + "a" * 26 + "_" + "b" * 43
    assert key not in redact_text(f"token {key}")


def test_secretbox_rotation_and_context_binding():
    old = Keyring.parse(f"k1:{generate_key()}")
    box = SecretBox(old)
    token = box.encrypt("hunter2", "webhook:whk_1")
    assert box.decrypt(token, "webhook:whk_1") == "hunter2"
    with pytest.raises(Exception):
        box.decrypt(token, "webhook:whk_2")
    # Rotation: new key first, old still decrypts; re-encryption moves to the new kid.
    k1 = old.kids[0]
    spec = f"k2:{generate_key()},{k1}:" + __import__("base64").urlsafe_b64encode(old.key(k1)).decode()
    box2 = SecretBox(Keyring.parse(spec))
    assert box2.decrypt(token, "webhook:whk_1") == "hunter2"
    assert box2.needs_rotation(token)
    fresh = box2.encrypt("hunter2", "webhook:whk_1")
    assert fresh.split(".")[1] == "k2" and not box2.needs_rotation(fresh)
    with pytest.raises(ConfigurationError):
        SecretBox(Keyring.parse(f"k3:{generate_key()}")).decrypt(token, "webhook:whk_1")


def test_secret_refs(monkeypatch, tmp_path):
    monkeypatch.setenv("AX_TEST_SECRET", "abc")
    assert resolve_secret("env:AX_TEST_SECRET") == "abc"
    f = tmp_path / "s"
    f.write_text("xyz\n")
    assert resolve_secret(f"file:{f}") == "xyz"
    with pytest.raises(ConfigurationError):
        resolve_secret("vault:foo")


def test_settings_env_overrides_and_validation(tmp_path):
    cfg = tmp_path / "a.toml"
    cfg.write_text('mode = "multi"\n[security]\nsession_ttl_hours = 4\n')
    s = load_settings(
        cfg,
        environ={
            "AXENTRA__SECURITY__ALLOWED_ORIGINS": '["https://studio.example"]',
            "AXENTRA__DATABASE__POOL_MAX": "3",
        },
    )
    assert s.mode.value == "multi" and s.security.session_ttl_hours == 4 and s.database.pool_max == 3
    assert s.security.allowed_origins == ["https://studio.example"]
    with pytest.raises(ConfigurationError):
        load_settings(None, environ={}, modules=["identity"])
    with pytest.raises(ConfigurationError):
        load_settings(None, environ={}, unknown_key=1)


def test_production_requires_secure_configuration():
    s = load_settings(None, environ={}, environment="production")
    with pytest.raises(ConfigurationError) as exc:
        s.validate_security()
    msg = str(exc.value)
    assert "https" in msg and "master_keys_ref" in msg
    ok = load_settings(
        None,
        environ={},
        environment="production",
        security={
            "public_url": "https://api.example",
            "master_keys_ref": "env:K",
            "allowed_origins": ["https://studio.example"],
        },
    )
    ok.validate_security()
    bad = load_settings(None, environ={}, security={"allowed_origins": ["*"]})
    with pytest.raises(ConfigurationError):
        bad.validate_security()


def test_notify_invitation_accept_url_validation():
    assert load_settings(None, environ={}).notify.invitation_accept_url is None
    assert load_settings(None, environ={}).invitation_accept_base == "http://127.0.0.1:8080/accept-invitation"
    s = load_settings(
        None,
        environ={"AXENTRA__NOTIFY__INVITATION_ACCEPT_URL": " https://studio.example/invitations/accept "},
    )
    assert s.notify.invitation_accept_url == "https://studio.example/invitations/accept"
    assert s.invitation_accept_base == "https://studio.example/invitations/accept"
    assert (
        load_settings(None, environ={}, notify={"invitation_accept_url": ""}).notify.invitation_accept_url
        is None
    )
    for bad in (
        "javascript:alert(1)",
        "ftp://studio.example/x",
        "/invitations/accept",
        "https://",
        "https://studio.example/a b",
        "https://studio.example/accept#frag",
    ):
        with pytest.raises(ConfigurationError):
            load_settings(None, environ={}, notify={"invitation_accept_url": bad})
    # A fragment is fine when the token is placed with {token} (hash-routed frontends).
    load_settings(
        None, environ={}, notify={"invitation_accept_url": "https://s.example/#/accept?token={token}"}
    )
    prod = {
        "environment": "production",
        "security": {
            "public_url": "https://api.example",
            "master_keys_ref": "env:K",
            "allowed_origins": ["https://studio.example"],
        },
    }
    with pytest.raises(ConfigurationError, match=r"notify\.invitation_accept_url must use https"):
        load_settings(
            None,
            environ={},
            notify={"invitation_accept_url": "http://studio.example/invitations/accept"},
            **prod,
        ).validate_security()
    load_settings(
        None,
        environ={},
        notify={"invitation_accept_url": "https://studio.example/invitations/accept"},
        **prod,
    ).validate_security()


def test_account_url_setting_and_links():
    from axentra.config.settings import load_settings
    from axentra.core.errors import ConfigurationError

    s = load_settings(None, environ={})
    assert s.account_link("/reset-password", "axpwr_a/b") == (
        "http://127.0.0.1:8080/reset-password?token=axpwr_a%2Fb"
    )
    # Falls back to the origin of the invitation link (split origins), then to its own setting.
    s = load_settings(None, environ={}, notify={"invitation_accept_url": "https://studio.example/inv/accept"})
    assert s.account_link("/verify-email", "t") == "https://studio.example/verify-email?token=t"
    s = load_settings(
        None,
        environ={},
        notify={
            "invitation_accept_url": "https://studio.example/x",
            "account_url": "https://acc.example/app/",
        },
    )
    assert s.account_link("/verify-email", "t") == "https://acc.example/app/verify-email?token=t"
    for bad in ("acc.example", "javascript:alert(1)", "https://acc.example/?a=1", "https://acc.example/#x"):
        with pytest.raises(ConfigurationError):
            load_settings(None, environ={}, notify={"account_url": bad})
    prod = {
        "environment": "production",
        "security": {
            "public_url": "https://api.example",
            "master_keys_ref": "env:K",
            "allowed_origins": ["https://studio.example"],
        },
    }
    with pytest.raises(ConfigurationError, match=r"notify\.account_url must use https"):
        load_settings(
            None, environ={}, notify={"account_url": "http://studio.example"}, **prod
        ).validate_security()
    load_settings(
        None, environ={}, notify={"account_url": "https://studio.example"}, **prod
    ).validate_security()
