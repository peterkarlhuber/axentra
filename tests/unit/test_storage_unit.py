from __future__ import annotations

import os
from pathlib import Path
import time

import pytest

from axentra.config.secrets import Keyring, generate_key
from axentra.core.errors import NotFound, ValidationFailed
from axentra.storage import safety
from axentra.storage.backends import LocalBackend, ObjectNotFound, check_key
from axentra.storage.service import _Meter, _peek, check_metadata
from axentra.storage.tokens import DownloadClaims, DownloadSigner


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../etc/passwd", "passwd"),
        ("C:\\Windows\\system32\\cmd", "cmd"),
        ("..", "file"),
        ("", "file"),
        (None, "file"),
        ("a\r\nb\x00c.txt", "abc.txt"),
        ('x<y>:"z"|?*.txt', "x_y___z____.txt"),
        ("  spaced   name .  ", "spaced name"),
        ("\u202eevil\u202d.txt", "evil.txt"),
        (".env", ".env"),
    ],
)
def test_sanitize_name(raw, expected):
    assert safety.sanitize_name(raw) == expected


def test_sanitize_name_truncates_utf8_and_keeps_extension():
    name = safety.sanitize_name("ü" * 300 + ".pdf")
    assert len(name.encode()) <= 255 and name.endswith(".pdf")


def test_sniffing_and_type_choice():
    assert safety.sniff(b"\x89PNG\r\n\x1a\n....") == "image/png"
    assert safety.sniff(b"\xef\xbb\xbf  <!DOCTYPE HTML><p>") == "text/html"
    assert safety.sniff(b"<?xml version='1.0'?>\n<svg/>") == "image/svg+xml"
    assert safety.sniff(b"<!-- c --><script>") == "text/html"
    assert safety.sniff(b"MZ\x90") == "application/x-msdownload"
    assert safety.sniff(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "image/webp"
    assert safety.sniff(b"just text") is None
    assert safety.choose_content_type(None, None) == "application/octet-stream"
    assert safety.choose_content_type("image/png", "application/pdf") == "application/pdf"
    assert (
        safety.choose_content_type(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip"
        )
        == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    assert safety.normalize_content_type("Text/Plain; charset=utf-8") == "text/plain"
    assert safety.normalize_content_type("bad type\r\nX: y") is None
    assert safety.type_allowed("image/png", ["image/*"]) and not safety.type_allowed(
        "text/plain", ["image/*"]
    )
    assert safety.type_allowed("text/plain", [])


def test_served_content_type_and_disposition():
    assert safety.served_content_type("application/xml") == "application/octet-stream"
    assert safety.served_content_type("text/html") == "application/octet-stream"
    assert safety.served_content_type("application/atom+xml") == "application/octet-stream"
    assert safety.served_content_type("image/png") == "image/png"
    cd = safety.content_disposition('evil"\r\nSet-Cookie: x=1.txt')
    assert "\r" not in cd and "\n" not in cd and cd.startswith('attachment; filename="')
    assert cd.count('"') == 2
    assert "filename*=UTF-8''" in safety.content_disposition("ä.txt")


def test_metadata_limits():
    assert check_metadata({"a": 1, "b.c": "x", "d": None, "e": True}) == {
        "a": 1,
        "b.c": "x",
        "d": None,
        "e": True,
    }
    for bad in ({"a": {"nested": 1}}, {"a b": 1}, {str(i): i for i in range(65)}, {"a": "x" * 1025}, [1]):
        with pytest.raises(ValidationFailed):
            check_metadata(bad)  # type: ignore[arg-type]


def test_meter_and_peek():
    head, rest = _peek(iter([b"ab", b"cd", b"ef"]), 3)
    assert head == b"abc" and b"".join(rest) == b"abcdef"
    m = _Meter(iter([b"x" * 10, b"y" * 10]), max_bytes=15, quota_remaining=None)
    from axentra.core.errors import PayloadTooLarge, QuotaExceeded

    with pytest.raises(PayloadTooLarge):
        list(m)
    with pytest.raises(QuotaExceeded):
        list(_Meter(iter([b"x" * 10]), max_bytes=100, quota_remaining=5))


@pytest.mark.parametrize(
    "key", ["../x", "/abs", "a/../b", "a\\b", "a/./b", "", "a//b", "a/b/", "é", "a" * 200]
)
def test_check_key_refuses_unsafe_keys(key):
    with pytest.raises(ValueError):
        check_key(key)


def test_local_backend_atomic_write_and_reads(tmp_path: Path):
    be = LocalBackend(tmp_path / "root")
    be.put("p/t/f1", [b"hello ", b"world"], content_type="text/plain")
    assert b"".join(be.get("p/t/f1")) == b"hello world"
    assert be.exists("p/t/f1") and list(be.list_keys()) == ["p/t/f1"]
    assert oct((tmp_path / "root" / "p").stat().st_mode & 0o777) == "0o700"

    def failing():
        yield b"partial"
        raise RuntimeError("client went away")

    with pytest.raises(RuntimeError):
        be.put("p/t/f2", failing(), content_type="text/plain")
    assert not be.exists("p/t/f2")
    assert [p.name for p in (tmp_path / "root" / "p" / "t").iterdir()] == ["f1"]
    # Overwrite is atomic: a failed rewrite keeps the old content.
    with pytest.raises(RuntimeError):
        be.put("p/t/f1", failing(), content_type="text/plain")
    assert b"".join(be.get("p/t/f1")) == b"hello world"
    with pytest.raises(ObjectNotFound):
        be.get("p/t/missing")
    assert be.delete("p/t/f1") is True and be.delete("p/t/f1") is False
    assert isinstance(ObjectNotFound("x"), NotFound)


def test_local_backend_refuses_symlink_escape(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_bytes(b"top secret")
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(outside, root / "p")
    be = LocalBackend(root)
    with pytest.raises(ValueError):
        be.get("p/secret")
    with pytest.raises(ValueError):
        be.put("p/new", [b"x"], content_type="text/plain")
    assert not (outside / "new").exists()
    (root / "q").mkdir()
    os.symlink(outside / "secret", root / "q" / "link")
    with pytest.raises(ObjectNotFound):
        be.get("q/link")


def test_local_backend_temp_cleanup(tmp_path: Path):
    be = LocalBackend(tmp_path)
    old = tmp_path / ".tmp-old"
    old.write_bytes(b"x")
    os.utime(old, (time.time() - 7200, time.time() - 7200))
    (tmp_path / ".tmp-new").write_bytes(b"x")
    assert be.cleanup_temporary(3600) == 1
    assert (tmp_path / ".tmp-new").exists()


def test_download_tokens_rotation_tamper_expiry():
    k1, k2 = generate_key(), generate_key()
    old = DownloadSigner(Keyring.parse(f"a1:{k1}"))
    claims = DownloadClaims("fil_x", "prd_x", "ten_x", int(time.time()) + 60)
    token = old.sign(claims)
    rotated = DownloadSigner(Keyring.parse(f"b2:{k2},a1:{k1}"))
    assert rotated.verify(token) == claims
    assert rotated.sign(claims).split(".")[1] == "b2"
    with pytest.raises(NotFound):
        DownloadSigner(Keyring.parse(f"b2:{k2}")).verify(token)
    with pytest.raises(NotFound):
        old.verify(token, now=claims.expires_at + 1)
    parts = token.split(".")
    for bad in (
        ".".join([parts[0], parts[1], parts[2] + "x", parts[3]]),
        ".".join(["d2", *parts[1:]]),
        token + ".x",
        "",
    ):
        with pytest.raises(NotFound):
            old.verify(bad)
    # The derived key is purpose-bound: it differs from the raw keyring key.
    assert old._key("a1") != Keyring.parse(f"a1:{k1}").key("a1")


def test_content_policy_parsing_and_classification():
    import pytest

    from axentra.core.errors import ValidationFailed
    from axentra.storage.policy import check_product_settings, lenient_policy, parse_policy

    p = parse_policy(None, installation_inert=False)
    assert p.blocked_types == "refuse" and p.blocked_types_source == "installation"
    assert parse_policy({}, installation_inert=True).blocked_types == "store_inert"
    p = parse_policy(
        {"blocked_types": "refuse", "blocked_extensions": [".PY"], "inert_extensions": ["sh"]},
        installation_inert=True,
    )
    assert p.blocked_types == "refuse" and p.blocked_types_source == "product"
    assert p.extension_blocked("py") and p.extension_blocked("html") and not p.extension_blocked("txt")
    assert p.store_inert("sh") and not p.store_inert("html")
    for bad in (
        {"blocked_types": "inline"},
        {"blocked_extensions": "py"},
        {"inert_extensions": ["../x"]},
        {"blocked_content_types": ["not a type"]},
        {"inert_extensions": ["x"] * 101},
    ):
        with pytest.raises(ValidationFailed):
            parse_policy(bad, installation_inert=False)
        with pytest.raises(ValidationFailed):
            check_product_settings({"storage": bad})
        # Stored values that are invalid never loosen the policy.
        assert lenient_policy(bad, installation_inert=False).blocked_types == "refuse"
    check_product_settings({"storage": "legacy"})  # non-object values were never validated
    check_product_settings({})
