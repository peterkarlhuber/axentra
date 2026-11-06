"""Built-in default templates (code defaults, version 0).

A product overrides a built-in template by creating a template with the same key; deleting the
override restores the default.
"""

from __future__ import annotations

from typing import Any

INVITATION = "invitation"
PRODUCT_INVITATION = "product_invitation"
PASSWORD_RESET = "password_reset"  # noqa: S105 - a template key, not a secret  # nosec B105
EMAIL_VERIFICATION = "email_verification"

#: Template keys only Axentra itself may send (never through ``POST .../notify/send``), whether or
#: not a product overrides their content: their variables (e.g. ``accept_url``) must never be
#: chosen by an API caller.
SYSTEM_ONLY_TEMPLATES: frozenset[str] = frozenset(
    {INVITATION, PRODUCT_INVITATION, PASSWORD_RESET, EMAIL_VERIFICATION}
)
#: Templates that carry a link to take over an account: a product cannot override them (an
#: override could send the link elsewhere, e.g. in an image URL), and only callers with the
#: platform permission ``users:manage`` see them in the local mailbox.
ACCOUNT_TEMPLATES: frozenset[str] = frozenset({PASSWORD_RESET, EMAIL_VERIFICATION})

BUILTIN_TEMPLATES: dict[str, dict[str, Any]] = {
    INVITATION: {
        "channel": "email",
        "category": "transactional",
        "name": "Tenant invitation",
        "description": "Sent when someone is invited to a tenant.",
        "sensitive": True,
        "variables": ["product_name", "tenant_name", "inviter_name", "role", "accept_url", "expires_at"],
        "sample_data": {
            "product_name": "Example",
            "tenant_name": "Acme Inc.",
            "inviter_name": "Alex",
            "role": "member",
            "accept_url": "https://app.example.com/accept-invitation?token=axinv_sample",
            "expires_at": "2026-01-01 12:00 UTC",
        },
        "variants": {
            "en": {
                "subject": "{{ inviter_name }} invited you to {{ tenant_name }} on {{ product_name }}",
                "text": (
                    "Hello,\n\n{{ inviter_name }} invited you to join {{ tenant_name }} on {{ product_name }}"
                    " as {{ role }}.\n\nAccept the invitation:\n{{ accept_url }}\n\n"
                    "The invitation expires on {{ expires_at }}. If you did not expect it, ignore this email.\n"
                ),
                "html": (
                    "<p>Hello,</p><p>{{ inviter_name }} invited you to join <strong>{{ tenant_name }}</strong>"
                    " on {{ product_name }} as {{ role }}.</p>"
                    '<p><a href="{{ accept_url }}">Accept the invitation</a></p>'
                    "<p>The invitation expires on {{ expires_at }}. If you did not expect it, ignore this"
                    " email.</p>"
                ),
            },
            "de": {
                "subject": "{{ inviter_name }} hat Sie zu {{ tenant_name }} auf {{ product_name }} eingeladen",
                "text": (
                    "Hallo,\n\n{{ inviter_name }} hat Sie eingeladen, {{ tenant_name }} auf {{ product_name }}"
                    " als {{ role }} beizutreten.\n\nEinladung annehmen:\n{{ accept_url }}\n\n"
                    "Die Einladung läuft am {{ expires_at }} ab. Falls Sie sie nicht erwartet haben,"
                    " ignorieren Sie diese E-Mail.\n"
                ),
                "html": (
                    "<p>Hallo,</p><p>{{ inviter_name }} hat Sie eingeladen, <strong>{{ tenant_name }}</strong>"
                    " auf {{ product_name }} als {{ role }} beizutreten.</p>"
                    '<p><a href="{{ accept_url }}">Einladung annehmen</a></p>'
                    "<p>Die Einladung läuft am {{ expires_at }} ab. Falls Sie sie nicht erwartet haben,"
                    " ignorieren Sie diese E-Mail.</p>"
                ),
            },
        },
    },
    PRODUCT_INVITATION: {
        "channel": "email",
        "category": "transactional",
        "name": "Product team invitation",
        "description": "Sent when someone is invited to a product's team (operators).",
        "sensitive": True,
        "variables": ["product_name", "inviter_name", "role", "accept_url", "expires_at"],
        "sample_data": {
            "product_name": "Example",
            "inviter_name": "Alex",
            "role": "product_admin",
            "accept_url": "https://app.example.com/accept-invitation?token=axpinv_sample",
            "expires_at": "2026-01-01 12:00 UTC",
        },
        "variants": {
            "en": {
                "subject": "{{ inviter_name }} invited you to the {{ product_name }} team",
                "text": (
                    "Hello,\n\n{{ inviter_name }} invited you to join the team of {{ product_name }}"
                    " as {{ role }}.\n\nAccept the invitation:\n{{ accept_url }}\n\n"
                    "The invitation expires on {{ expires_at }}. If you did not expect it, ignore this email.\n"
                ),
                "html": (
                    "<p>Hello,</p><p>{{ inviter_name }} invited you to join the team of"
                    " <strong>{{ product_name }}</strong> as {{ role }}.</p>"
                    '<p><a href="{{ accept_url }}">Accept the invitation</a></p>'
                    "<p>The invitation expires on {{ expires_at }}. If you did not expect it, ignore this"
                    " email.</p>"
                ),
            },
            "de": {
                "subject": "{{ inviter_name }} hat Sie in das Team von {{ product_name }} eingeladen",
                "text": (
                    "Hallo,\n\n{{ inviter_name }} hat Sie eingeladen, dem Team von {{ product_name }}"
                    " als {{ role }} beizutreten.\n\nEinladung annehmen:\n{{ accept_url }}\n\n"
                    "Die Einladung läuft am {{ expires_at }} ab. Falls Sie sie nicht erwartet haben,"
                    " ignorieren Sie diese E-Mail.\n"
                ),
                "html": (
                    "<p>Hallo,</p><p>{{ inviter_name }} hat Sie eingeladen, dem Team von"
                    " <strong>{{ product_name }}</strong> als {{ role }} beizutreten.</p>"
                    '<p><a href="{{ accept_url }}">Einladung annehmen</a></p>'
                    "<p>Die Einladung läuft am {{ expires_at }} ab. Falls Sie sie nicht erwartet haben,"
                    " ignorieren Sie diese E-Mail.</p>"
                ),
            },
        },
    },
    PASSWORD_RESET: {
        "channel": "email",
        "category": "security",
        "name": "Password reset",
        "description": "Sent when someone asks to reset the password of an account with this address.",
        "sensitive": True,
        "variables": ["product_name", "reset_url", "expires_at"],
        "sample_data": {
            "product_name": "Example",
            "reset_url": "https://app.example.com/reset-password?token=axpwr_sample",
            "expires_at": "2026-01-01 12:00 UTC",
        },
        "variants": {
            "en": {
                "subject": "Reset your {{ product_name }} password",
                "text": (
                    "Hello,\n\nsomeone asked to reset the password of your account. Choose a new password:\n"
                    "{{ reset_url }}\n\nThe link works once and expires on {{ expires_at }}. If you did not"
                    " ask for it, ignore this email: your password stays unchanged.\n"
                ),
                "html": (
                    "<p>Hello,</p><p>someone asked to reset the password of your account.</p>"
                    '<p><a href="{{ reset_url }}">Choose a new password</a></p>'
                    "<p>The link works once and expires on {{ expires_at }}. If you did not ask for it,"
                    " ignore this email: your password stays unchanged.</p>"
                ),
            },
            "de": {
                "subject": "Passwort für {{ product_name }} zurücksetzen",
                "text": (
                    "Hallo,\n\njemand hat angefordert, das Passwort Ihres Kontos zurückzusetzen. Neues"
                    " Passwort wählen:\n{{ reset_url }}\n\nDer Link funktioniert einmal und läuft am"
                    " {{ expires_at }} ab. Falls Sie das nicht angefordert haben, ignorieren Sie diese"
                    " E-Mail: Ihr Passwort bleibt unverändert.\n"
                ),
                "html": (
                    "<p>Hallo,</p><p>jemand hat angefordert, das Passwort Ihres Kontos zurückzusetzen.</p>"
                    '<p><a href="{{ reset_url }}">Neues Passwort wählen</a></p>'
                    "<p>Der Link funktioniert einmal und läuft am {{ expires_at }} ab. Falls Sie das nicht"
                    " angefordert haben, ignorieren Sie diese E-Mail: Ihr Passwort bleibt unverändert.</p>"
                ),
            },
        },
    },
    EMAIL_VERIFICATION: {
        "channel": "email",
        "category": "security",
        "name": "Email verification",
        "description": "Sent when a user asks to confirm their email address.",
        "sensitive": True,
        "variables": ["product_name", "verify_url", "expires_at"],
        "sample_data": {
            "product_name": "Example",
            "verify_url": "https://app.example.com/verify-email?token=axemv_sample",
            "expires_at": "2026-01-01 12:00 UTC",
        },
        "variants": {
            "en": {
                "subject": "Confirm your email address for {{ product_name }}",
                "text": (
                    "Hello,\n\nconfirm that this is your email address:\n{{ verify_url }}\n\n"
                    "The link works once and expires on {{ expires_at }}. If you did not ask for it,"
                    " ignore this email.\n"
                ),
                "html": (
                    "<p>Hello,</p><p>confirm that this is your email address.</p>"
                    '<p><a href="{{ verify_url }}">Confirm the email address</a></p>'
                    "<p>The link works once and expires on {{ expires_at }}. If you did not ask for it,"
                    " ignore this email.</p>"
                ),
            },
            "de": {
                "subject": "E-Mail-Adresse für {{ product_name }} bestätigen",
                "text": (
                    "Hallo,\n\nbestätigen Sie, dass dies Ihre E-Mail-Adresse ist:\n{{ verify_url }}\n\n"
                    "Der Link funktioniert einmal und läuft am {{ expires_at }} ab. Falls Sie das nicht"
                    " angefordert haben, ignorieren Sie diese E-Mail.\n"
                ),
                "html": (
                    "<p>Hallo,</p><p>bestätigen Sie, dass dies Ihre E-Mail-Adresse ist.</p>"
                    '<p><a href="{{ verify_url }}">E-Mail-Adresse bestätigen</a></p>'
                    "<p>Der Link funktioniert einmal und läuft am {{ expires_at }} ab. Falls Sie das"
                    " nicht angefordert haben, ignorieren Sie diese E-Mail.</p>"
                ),
            },
        },
    },
}
