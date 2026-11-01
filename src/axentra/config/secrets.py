"""Secret references and authenticated encryption with a versioned, rotatable keyring.

Secret references: ``env:NAME`` reads an environment variable, ``file:/path`` reads a file
(trailing newline stripped). Other providers (Vault, cloud KMS) plug in through
:class:`SecretProvider`.

Encryption: AES-256-GCM. A ciphertext is ``axs1.<kid>.<nonce b64>.<ciphertext+tag b64>``; the key
id is part of the associated data together with a caller-supplied context (e.g. the table and
row id), so a ciphertext cannot be moved to another row. The keyring holds several keys; the
first one encrypts, all of them decrypt. Rotation: add a new key in front, restart, run
``axentra secrets reencrypt`` (re-encrypts every stored value with the active key), then remove
the old key. This fixes the "central key cannot rotate" limitation known from Nodestro.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
import os
from pathlib import Path
import secrets as _secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from axentra.core.errors import ConfigurationError

PREFIX = "axs1"

SecretProvider = Callable[[str], str]


def _env_provider(name: str) -> str:
    value = os.environ.get(name)
    if value is None:
        raise ConfigurationError(f"secret environment variable {name} is not set")
    return value


def _file_provider(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").rstrip("\n")
    except OSError as exc:
        raise ConfigurationError(f"cannot read secret file {path}") from exc


PROVIDERS: dict[str, SecretProvider] = {"env": _env_provider, "file": _file_provider}


def resolve_secret(ref: str, providers: Mapping[str, SecretProvider] | None = None) -> str:
    scheme, sep, rest = ref.partition(":")
    table = providers or PROVIDERS
    if not sep or scheme not in table:
        raise ConfigurationError(f"unsupported secret reference scheme {scheme!r} (use env: or file:)")
    return table[scheme](rest)


def generate_key() -> str:
    return base64.urlsafe_b64encode(_secrets.token_bytes(32)).decode().rstrip("=")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class Keyring:
    """Versioned AES-256 keys: ``kid:base64key,kid2:base64key`` (first = active)."""

    def __init__(self, keys: list[tuple[str, bytes]]) -> None:
        if not keys:
            raise ConfigurationError("the keyring needs at least one key")
        seen: set[str] = set()
        for kid, key in keys:
            if not kid.isalnum():
                raise ConfigurationError("key ids must be alphanumeric")
            if kid in seen:
                raise ConfigurationError(f"duplicate key id {kid}")
            if len(key) != 32:
                raise ConfigurationError(f"key {kid} must be 32 bytes (256 bit)")
            seen.add(kid)
        self._keys = dict(keys)
        self.active_kid = keys[0][0]

    @classmethod
    def parse(cls, spec: str) -> Keyring:
        keys: list[tuple[str, bytes]] = []
        for item in spec.split(","):
            item = item.strip()
            if not item:
                continue
            kid, sep, b64 = item.partition(":")
            if not sep:
                raise ConfigurationError("keyring entries must look like kid:base64key")
            try:
                keys.append((kid, _b64d(b64)))
            except ValueError as exc:
                raise ConfigurationError(f"key {kid} is not valid base64") from exc
        return cls(keys)

    @property
    def kids(self) -> list[str]:
        return list(self._keys)

    def key(self, kid: str) -> bytes:
        try:
            return self._keys[kid]
        except KeyError:
            raise ConfigurationError(
                f"unknown encryption key id {kid}; keep old keys until re-encryption"
            ) from None


class SecretBox:
    def __init__(self, keyring: Keyring) -> None:
        self.keyring = keyring

    def encrypt(self, plaintext: str, context: str) -> str:
        kid = self.keyring.active_kid
        nonce = _secrets.token_bytes(12)
        ct = AESGCM(self.keyring.key(kid)).encrypt(
            nonce, plaintext.encode(), f"{PREFIX}|{kid}|{context}".encode()
        )
        enc = base64.urlsafe_b64encode
        return f"{PREFIX}.{kid}.{enc(nonce).decode()}.{enc(ct).decode()}"

    def decrypt(self, token: str, context: str) -> str:
        try:
            prefix, kid, nonce_b64, ct_b64 = token.split(".")
        except ValueError:
            raise ValueError("not an Axentra ciphertext") from None
        if prefix != PREFIX:
            raise ValueError("unsupported ciphertext version")
        data = AESGCM(self.keyring.key(kid)).decrypt(
            _b64d(nonce_b64), _b64d(ct_b64), f"{PREFIX}|{kid}|{context}".encode()
        )
        return data.decode()

    def needs_rotation(self, token: str) -> bool:
        parts = token.split(".")
        return len(parts) != 4 or parts[1] != self.keyring.active_kid


def keyring_from_settings(
    master_keys: str | None, master_keys_ref: str | None, *, production: bool
) -> Keyring:
    if master_keys_ref:
        return Keyring.parse(resolve_secret(master_keys_ref))
    if master_keys:
        return Keyring.parse(master_keys)
    if production:
        raise ConfigurationError("security.master_keys_ref is required in production")
    # Development/test only: an ephemeral key, so encrypted values do not survive a restart.
    return Keyring([("dev", _secrets.token_bytes(32))])
