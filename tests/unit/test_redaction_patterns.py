"""More secret shapes are redacted from logs, errors and audit payloads (MUP-ONA VB-4)."""

from __future__ import annotations

import pytest

from axentra.core.redaction import REDACTED, redact, redact_text

SECRETS = [
    ("whsec_" + "Ab3_-" * 9, "whsec_" + "Ab3_-" * 9),
    ("signing secret whsec%5FAb3dEf6hIj9kLm2nOp5q", "whsec%5FAb3dEf6hIj9kLm2nOp5q"),
    ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
    ("{'Authorization': 'Basic dXNlcjpwYXNzd29yZA=='}", "dXNlcjpwYXNzd29yZA=="),
    ("proxy-authorization: basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
    ("Cookie: __Host-axentra-session=s3ss10n-v4lue; theme=dark", "s3ss10n-v4lue"),
    ("Set-Cookie: axentra-login=l0g1n-v4lue; Path=/; HttpOnly", "l0g1n-v4lue"),
    ("request carried __Host-axentra-session=s3ss10n-v4lue in the header", "s3ss10n-v4lue"),
    ("grant_type=password&username=a&password=hunter2-hunter2", "hunter2-hunter2"),
    ('{"body": "new_password=Correct-Horse-9"}', "Correct-Horse-9"),
    ("client_id=abc&client_secret=c1i3nt-s3cr3t&code=x", "c1i3nt-s3cr3t"),
    ("return_to=%2Fx%3Fclient%5Fsecret%3Dc1i3nt-s3cr3t", "c1i3nt-s3cr3t"),
    # B-02: every prefixed token Axentra issues.
    ("invited with axinv_" + "Inv-_" * 9, "Inv-_" * 9),
    ("product invitation axpinv_" + "Pinv0" * 9, "Pinv0" * 9),
    ("reset link /reset?x=1#axpwr_" + "Pwr9-" * 9, "Pwr9-" * 9),
    ("verify axemv_" + "Emv7_" * 9, "Emv7_" * 9),
    ("setup token axsetup_" + "Setup" * 9, "Setup" * 9),
    ("encoded axpinv%5F" + "Pinv1" * 9, "Pinv1" * 9),
    # B-01: signed download tokens in a request line (uvicorn access log) and percent-encoded.
    (
        '127.0.0.1:5000 - "GET /v1/files/download/d1.k1.eyJmIjoiZmlsXzEifQ.' + "M4c-_" * 9 + ' HTTP/1.1" 200',
        "M4c-_" * 9,
    ),
    ("next=%2Fv1%2Ffiles%2Fdownload%2Fd1%2Ek1%2EeyJmIjoiZmlsXzEifQ%2E" + "M4c" * 15, "M4c" * 15),
    ("next=%252Fv1%252Ffiles%252Fdownload%252Fd1.k1.eyJmIjoiZmlsXzEifQ." + "M4d" * 15, "M4d" * 15),
    ("x_d1.k1.eyJmIjoiZmlsXzEifQ." + "M4e" * 15, "M4e" * 15),
]

HARMLESS = [
    "basic information about the webhook",
    "The password must be at least 12 characters",
    "Set the client secret in the provider configuration",
    "cookie policy: strict",
    "authorization failed: missing permission records:write",
    "whsec_short",
    "a = b, password reset requested",
    "GET /v1/products?page=2&limit=50",
    "GET /v1/files/download/garbage",
    "version d1.2.3 of the schema",
]


# MUP-ONA T-A7-3
@pytest.mark.parametrize(("text", "secret"), SECRETS, ids=[s[1][:12] for s in SECRETS])
def test_secret_is_redacted(text: str, secret: str) -> None:
    out = redact_text(text)
    assert secret not in out
    assert REDACTED in out


# MUP-ONA T-A7-3
@pytest.mark.parametrize("text", HARMLESS)
def test_harmless_text_is_unchanged(text: str) -> None:
    assert redact_text(text) == text


# MUP-ONA T-A7-3
def test_the_name_stays_visible() -> None:
    assert redact_text("Authorization: Basic dXNlcjpwYXNz") == f"Authorization: Basic {REDACTED}"
    assert redact_text("password=x1&next=/") == f"password={REDACTED}&next=/"
    assert redact_text("axentra-session=abc; Path=/") == f"axentra-session={REDACTED}; Path=/"


# MUP-ONA T-A7-3
def test_nested_payloads_are_redacted() -> None:
    payload = {"detail": ["sent with Authorization: Basic dXNlcjpwYXNz", {"note": "client_secret=abc123"}]}
    out = redact(payload)
    assert "dXNlcjpwYXNz" not in str(out) and "abc123" not in str(out)


# MUP-ONA T-VEC-2: a password or client secret as a quoted key with a quoted value (the shared vector
# redact-password-quoted-json-text found that only the ``name=value`` form was redacted).
@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ('{"password": "Correct-Horse-9"}', "Correct-Horse-9"),
        ("{'new_password': 'Correct Horse 9'}", "Correct Horse 9"),
        ('{"client_secret":"c1i3nt-s3cr3t"}', "c1i3nt-s3cr3t"),
        ('body {"Password": "it\'s \\"quoted\\" 9", "next": 1}', 'quoted\\" 9'),
    ],
)
def test_quoted_password_values_are_redacted(text: str, secret: str) -> None:
    out = redact_text(text)
    assert secret not in out
    assert REDACTED in out


# MUP-ONA T-VEC-2
@pytest.mark.parametrize(
    "text",
    [
        '{"password_policy": "strict"}',
        'password: "see the policy"',
        '{"password": ""}',
        "'passwords' are rotated",
    ],
)
def test_quoted_names_without_a_secret_value_are_unchanged(text: str) -> None:
    assert redact_text(text) == text


AWS = [
    (
        "{'Authorization': b'AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEKEY01/20261114/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;x-amz-date, Signature=51c38408d758a3da5f8e92104fe8060bcefd21ebda89246d23d2c1a69da6525e'}",
        ["AKIAEXAMPLEKEY01", "51c38408d758a3da5f8e92104fe8060bcefd21ebda89246d23d2c1a69da6525e"],
    ),
    (
        "Authorization: AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEKEY01/x, Signature=deadbeefdeadbeefdeadbeef",
        ["AKIAEXAMPLEKEY01", "deadbeefdeadbeefdeadbeef"],
    ),
    (
        "GET /b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLEKEY01%2F20261114%2Fus-east-1"
        "&X-Amz-Date=20261114T000000Z&X-Amz-Signature=0a1b2c3d4e5f60718293a4b5c6d7e8f9",
        ["AKIAEXAMPLEKEY01", "0a1b2c3d4e5f60718293a4b5c6d7e8f9"],
    ),
    ("{'X-Amz-Security-Token': b'FwoGZXIvYXdzEXAMPLEsessiontoken'}", ["FwoGZXIvYXdzEXAMPLEsessiontoken"]),
]


@pytest.mark.parametrize(("text", "secrets"), AWS)
def test_aws_sigv4_credentials_are_redacted(text: str, secrets: list[str]) -> None:
    out = redact_text(text)
    assert REDACTED in out
    for secret in secrets:
        assert secret not in out, out


def test_botocore_debug_records_are_redacted() -> None:
    """botocore logs request headers at DEBUG (``log_level = "DEBUG"``); the JSON log must not carry them."""
    import logging

    from axentra.audit.logging import JsonFormatter

    record = logging.LogRecord(
        "botocore.endpoint", logging.DEBUG, __file__, 1, "Making request with params: %r", (AWS[0][0],), None
    )
    line = JsonFormatter().format(record)
    assert "AKIAEXAMPLEKEY01" not in line and "51c38408d758a3da" not in line
    assert "Making request with params" in line  # the rest of the record stays readable
