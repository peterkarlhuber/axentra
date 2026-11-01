# ADR 0011: Versioned encryption keyring with rotation

Status: accepted (Phase 0)

## Context

Some stored values must be decryptable (OIDC client data, webhook signing secrets, provider
credentials, planned in later modules). A single static key cannot be rotated without downtime
or data loss; Nodestro's central key had exactly this limitation.

## Decision

- AES-256-GCM via `cryptography`, 96-bit random nonces.
- A keyring `kid:base64key,...` from a secret reference (`security.master_keys_ref`); the first key
  encrypts, every key decrypts. Inline keys are refused in production.
- Ciphertext format `axs1.<kid>.<nonce>.<ciphertext+tag>`; associated data
  `axs1|<kid>|<context>`, where the caller passes a context such as table and row id, so values
  cannot be swapped between rows or purposes.
- Rotation: add the new key in front, restart, re-encrypt stored values, remove the old key.
  `SecretBox.needs_rotation()` identifies values under an old key; `axentra secrets reencrypt`
  (`--dry-run` for counts per key id) rewrites every registered encrypted column in batches
  (`axentra.data.reencrypt`; products register their columns with `ax.register_encrypted_column`).

## Consequences

- The keyring is as critical as the database and must be backed up separately
  ([BACKUP_RESTORE](../operations/BACKUP_RESTORE.md)).
- Removing a key that is still referenced makes those values unreadable; the error names the
  missing key id.
