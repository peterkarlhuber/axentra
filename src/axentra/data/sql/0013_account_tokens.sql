-- Password reset and email verification.
--
-- axentra_account_tokens holds single-use tokens sent by email: only the SHA-256 of the token is
-- stored (like sessions, setup and invitation tokens), each token expires, and `used_at` marks it
-- spent. `email` is the address the token was sent to: a token is valid only while the user still
-- has that address. Like axentra_users and axentra_sessions this is a global table without
-- row-level security (users are not product- or tenant-scoped); the identity service is the only
-- reader and writer.
--
-- axentra_users.email_verified_at records when the user proved control of their address (an
-- email verification link, or a password reset link, which also arrives by email).

CREATE TABLE axentra_account_tokens (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES axentra_users (id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('password_reset', 'email_verification')),
    token_hash text NOT NULL UNIQUE,
    email text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE INDEX axentra_account_tokens_open ON axentra_account_tokens (user_id, purpose)
    WHERE used_at IS NULL;

ALTER TABLE axentra_users ADD COLUMN email_verified_at timestamptz;
