from __future__ import annotations

import hashlib
import hmac


def hash_token(token: str) -> str:
    """SHA-256 of a high-entropy random token (session, invitation, setup, API key secret)."""
    return hashlib.sha256(token.encode()).hexdigest()


def token_matches(token: str, digest: str) -> bool:
    return hmac.compare_digest(hash_token(token), digest)
