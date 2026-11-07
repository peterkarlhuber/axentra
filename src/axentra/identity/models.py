from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class User(BaseModel):
    id: str
    email: str | None
    """``None`` for users without an email address (e.g. an external identity without a verified
    email claim); they cannot log in with a password or accept email-bound invitations."""
    name: str
    status: Literal["active", "disabled"]
    locale: str
    preferences: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None
    has_password: bool = False
    email_verified: bool = False
    """The user confirmed control of ``email`` (verification link or password reset link)."""
    platform_role: str | None = None

    @property
    def display(self) -> str:
        """A label for logs and audit events: the email, else the name, else the id."""
        return self.email or self.name or self.id


class ExternalIdentity(BaseModel):
    """An external (OIDC) identity linked to a user: ``provider`` is the issuer, ``subject`` its
    ``sub`` claim; ``email`` is the address the provider reported (empty when none, and kept for
    reference even when it was not verified)."""

    provider: str
    subject: str
    email: str
    created_at: datetime


class Session(BaseModel):
    id: str
    user_id: str
    auth_method: str
    ip: str | None
    user_agent: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    current: bool = False


class SessionInfo(BaseModel):
    """What ``GET /v1/auth/session`` returns: the user, the CSRF token and the expiry."""

    user: User
    session_id: str
    csrf_token: str
    expires_at: datetime
    platform_role: str | None


class NewSession(BaseModel):
    """A started session; ``token`` goes into the cookie and is never stored."""

    token: str
    info: SessionInfo


class AccountEmail(BaseModel):
    """A password reset or email verification token to send (never returned by the API)."""

    purpose: Literal["password_reset", "email_verification"]
    token_id: str
    token: str
    user_id: str
    email: str
    locale: str
    product_id: str
    expires_at: datetime
