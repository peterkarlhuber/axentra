"""Built-in default templates (code defaults, version 0).

A product overrides a built-in template by creating a template with the same key; deleting the
override restores the default.
"""

from __future__ import annotations

from typing import Any

INVITATION = "invitation"

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
    }
}
