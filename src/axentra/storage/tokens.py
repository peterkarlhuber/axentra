"""Signed download tokens for ``GET /v1/files/download/{token}``.

Format: ``d1.<kid>.<payload>.<mac>`` (base64url without padding). ``payload`` is compact JSON
``{"f": file_id, "p": product_id, "t": tenant_id, "e": expiry_unix}``; ``mac`` is HMAC-SHA256 over
``d1.<kid>.<payload>`` with a key derived (HKDF-SHA256, purpose-bound ``info``) from keyring key
``kid``. Every key of the keyring verifies, so tokens survive a key rotation until they expire.
Tokens are bearer credentials: whoever holds one can download that one file until it expires
(or until the file is deleted).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from axentra.config.secrets import Keyring
from axentra.core.errors import ConfigurationError, NotFound

VERSION = "d1"
_INFO = b"axentra/storage/download-token/v1"
MAX_TOKEN_LENGTH = 1024


@dataclass(frozen=True, slots=True)
class DownloadClaims:
    file_id: str
    product_id: str
    tenant_id: str
    expires_at: int


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class DownloadSigner:
    def __init__(self, keyring: Keyring) -> None:
        self.keyring = keyring
        self._keys: dict[str, bytes] = {}

    def _key(self, kid: str) -> bytes:
        if kid not in self._keys:
            self._keys[kid] = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(
                self.keyring.key(kid)
            )
        return self._keys[kid]

    def sign(self, claims: DownloadClaims) -> str:
        kid = self.keyring.active_kid
        payload = _b64e(
            json.dumps(
                {"f": claims.file_id, "p": claims.product_id, "t": claims.tenant_id, "e": claims.expires_at},
                separators=(",", ":"),
            ).encode()
        )
        head = f"{VERSION}.{kid}.{payload}"
        mac = hmac.new(self._key(kid), head.encode(), hashlib.sha256).digest()
        return f"{head}.{_b64e(mac)}"

    def verify(self, token: str, *, now: float | None = None) -> DownloadClaims:
        """Return the claims of a valid, unexpired token; any problem is a uniform ``NotFound``."""
        invalid = NotFound("download link not found or expired")
        if not token or len(token) > MAX_TOKEN_LENGTH:
            raise invalid
        parts = token.split(".")
        if len(parts) != 4 or parts[0] != VERSION:
            raise invalid
        _, kid, payload, mac = parts
        if kid not in self.keyring.kids:
            raise invalid
        try:
            key = self._key(kid)
            expected = hmac.new(key, f"{VERSION}.{kid}.{payload}".encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _b64d(mac)):
                raise invalid
            data = json.loads(_b64d(payload))
            claims = DownloadClaims(
                file_id=str(data["f"]),
                product_id=str(data["p"]),
                tenant_id=str(data["t"]),
                expires_at=int(data["e"]),
            )
        except (ValueError, KeyError, TypeError, ConfigurationError):
            raise invalid from None
        if claims.expires_at <= (time.time() if now is None else now):
            raise invalid
        return claims
