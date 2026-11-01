"""SmtpProvider against an in-process SMTP server on 127.0.0.1 (aiosmtpd) with STARTTLS and AUTH."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import ipaddress
import os
import socket
import ssl

import pytest

from axentra.config.settings import NotifySettings
from axentra.core.errors import ConfigurationError
from axentra.notify.providers import OutgoingMessage, ProviderError, SmtpProvider

aiosmtpd = pytest.importorskip("aiosmtpd")
from aiosmtpd.controller import Controller  # noqa: E402
from aiosmtpd.smtp import AuthResult  # noqa: E402


def _cert(tmp_path):  # type: ignore[no-untyped-def]
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return str(cert_path), str(key_path)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Handler:
    def __init__(self) -> None:
        self.messages: list[tuple[str, list[str], bytes]] = []

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):  # type: ignore[no-untyped-def]
        if address.startswith("reject"):
            return "550 5.1.1 no such user"
        if address.startswith("busy"):
            return "451 4.3.0 try later"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):  # type: ignore[no-untyped-def]
        self.messages.append((envelope.mail_from, list(envelope.rcpt_tos), envelope.content))
        return "250 Message accepted"


@pytest.fixture
def smtp_server(tmp_path):  # type: ignore[no-untyped-def]
    cert, key = _cert(tmp_path)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, key)
    handler = Handler()

    def auth(server, session, envelope, mechanism, auth_data):  # type: ignore[no-untyped-def]
        ok = auth_data.login == b"mailer" and auth_data.password == b"s3cret-pw"
        return AuthResult(success=ok)

    port = _free_port()
    controller = Controller(
        handler,
        hostname="127.0.0.1",
        port=port,
        tls_context=ctx,
        require_starttls=True,
        authenticator=auth,
        auth_require_tls=True,
    )
    controller.start()
    yield handler, port, cert
    controller.stop()


def _msg(to: str = "bob@example.com") -> OutgoingMessage:
    return OutgoingMessage(
        message_id="msg_01abc",
        product_id="prd_x",
        tenant_id=None,
        channel="email",
        sender="Axentra <no-reply@example.com>",
        recipient=to,
        subject="Hello Bob",
        text="plain body",
        html="<p>html body</p>",
    )


def _settings(port: int, cert: str, **kw):  # type: ignore[no-untyped-def]
    os.environ["AXENTRA_TEST_SMTP_PW"] = "s3cret-pw"
    base = {
        "provider": "smtp",
        "smtp_host": "127.0.0.1",
        "smtp_port": port,
        "smtp_username": "mailer",
        "smtp_password_ref": "env:AXENTRA_TEST_SMTP_PW",
        "smtp_ca_file": cert,
        "smtp_timeout_seconds": 10,
    }
    base.update(kw)
    return NotifySettings(**base)


def test_smtp_starttls_auth_and_delivery(smtp_server):
    handler, port, cert = smtp_server
    provider = SmtpProvider(_settings(port, cert), production=True)
    assert provider.check()
    msgid = provider.send(_msg())
    assert msgid.startswith("<") and msgid.endswith("@example.com>")
    (mail_from, rcpts, content) = handler.messages[0]
    assert mail_from == "no-reply@example.com" and rcpts == ["bob@example.com"]
    assert b"Subject: Hello Bob" in content and b"html body" in content and msgid.encode() in content


def test_smtp_errors_are_classified(smtp_server):
    _, port, cert = smtp_server
    provider = SmtpProvider(_settings(port, cert), production=False)
    with pytest.raises(ProviderError) as exc:
        provider.send(_msg("reject@example.com"))
    assert exc.value.permanent
    with pytest.raises(ProviderError) as exc:
        provider.send(_msg("busy@example.com"))
    assert not exc.value.permanent
    bad = SmtpProvider(_settings(port, cert, smtp_timeout_seconds=2), production=False)
    bad._password = "wrong"  # authentication failure: retried later (configuration problem)
    with pytest.raises(ProviderError) as exc:
        bad.send(_msg())
    assert not exc.value.permanent


def test_smtp_rejects_untrusted_certificate(smtp_server):
    _, port, _cert_path = smtp_server
    provider = SmtpProvider(_settings(port, None), production=False)  # system CAs only
    with pytest.raises(ProviderError) as exc:
        provider.send(_msg())
    assert not exc.value.permanent


def test_smtp_configuration_is_validated():
    with pytest.raises(ConfigurationError):
        SmtpProvider(
            NotifySettings(provider="smtp", smtp_host="mail.example.com", smtp_starttls=False),
            production=True,
        )
    with pytest.raises(ConfigurationError):
        SmtpProvider(NotifySettings(provider="smtp", smtp_username="u"), production=False)
    # Loopback relays without TLS are fine (e.g. a local MTA).
    SmtpProvider(NotifySettings(provider="smtp", smtp_host="127.0.0.1", smtp_starttls=False), production=True)


def test_connection_failure_is_transient():
    provider = SmtpProvider(
        NotifySettings(
            provider="smtp", smtp_host="127.0.0.1", smtp_port=_free_port(), smtp_timeout_seconds=2
        ),
        production=False,
    )
    with pytest.raises(ProviderError) as exc:
        provider.send(_msg())
    assert not exc.value.permanent
