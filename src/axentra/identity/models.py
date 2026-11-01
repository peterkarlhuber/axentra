from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class User(BaseModel):
    id: str
    email: str
    name: str
    status: Literal["active", "disabled"]
    locale: str
    preferences: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None
    has_password: bool = False
    platform_role: str | None = None


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
