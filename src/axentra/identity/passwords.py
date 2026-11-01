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


def check_policy(password: str, *, min_length: int, email: str = "") -> None:
    if len(password) < min_length:
        raise ValidationFailed(f"the password must have at least {min_length} characters")
    if len(password) > 1024:
        raise ValidationFailed("the password is too long")
    if email and password.lower() == email.lower():
        raise ValidationFailed("the password must not equal the email address")
    if len(set(password)) < 4:
        raise ValidationFailed("the password is too simple")
