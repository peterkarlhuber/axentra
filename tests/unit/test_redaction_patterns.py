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
