"""Password hashing with Argon2id (argon2-cffi defaults follow RFC 9106 recommendations)."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from axentra.core.errors import ValidationFailed

_HASHER = PasswordHasher()
# A real hash of a random value: verifying unknown accounts against it keeps the timing similar.
_DUMMY_HASH = _HASHER.hash("axentra-dummy-password-for-timing")


def hash_password(password: str) -> str:
    return _HASHER.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _HASHER.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _HASHER.check_needs_rehash(password_hash)


#: Upper bound for any password (the request models refuse longer input before hashing).
MAX_PASSWORD_LENGTH = 1024


def check_policy(password: str, *, min_length: int, email: str = "", field: str = "password") -> None:
    """Refuse a password that breaks the policy with a ``422 validation_failed``.

    The problem carries ``reason`` (``too_short``, ``too_long``, ``equals_email`` or ``too_simple``),
    ``min_length`` and ``errors=[{"loc": ["body", field], "msg": ...}]`` like a request validation
    error, so a client can mark the password field (``field`` is the request body member)."""
    if len(password) < min_length:
        reason, msg = "too_short", f"the password must have at least {min_length} characters"
    elif len(password) > MAX_PASSWORD_LENGTH:
        reason, msg = "too_long", "the password is too long"
    elif email and password.lower() == email.lower():
        reason, msg = "equals_email", "the password must not equal the email address"
    elif len(set(password)) < 4:
        reason, msg = "too_simple", "the password is too simple"
    else:
        return
    raise ValidationFailed(
        msg,
        extra={
            "reason": reason,
            "min_length": min_length,
            "errors": [{"loc": ["body", field], "msg": msg}],
        },
    )
