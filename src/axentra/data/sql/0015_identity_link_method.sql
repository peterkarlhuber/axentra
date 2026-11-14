-- How an external identity got linked to its user (owner decision I5, 2026-11-14).
--
-- A user with a platform role signs in through an identity provider only with an identity that a
-- platform admin linked explicitly (`explicit`) or that created the account (`signup`). An identity
-- linked by verified email (`email`) stops working when the user gets a platform role, so a provider
-- that is wrong about an address cannot reach a platform account, also not by an older link.
-- Identities from before this migration are `unknown` and treated like `email` for platform users:
-- a platform admin confirms them with `POST /v1/users/{user_id}/identities`.
ALTER TABLE axentra_user_identities
    ADD COLUMN linked_by text NOT NULL DEFAULT 'unknown'
    CHECK (linked_by IN ('unknown', 'email', 'explicit', 'signup'));
