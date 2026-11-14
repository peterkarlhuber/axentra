-- How an external identity got linked to its user (owner decision I5, 2026-11-14).
--
-- A user with a platform role signs in through an identity provider only with an identity that a
-- platform admin linked explicitly (`explicit`) or that created the account (`signup`). An identity
-- linked by verified email (`email`) stops working when the user gets a platform role, so a provider
-- that is wrong about an address cannot reach a platform account, also not by an older link.
ALTER TABLE axentra_user_identities
    ADD COLUMN linked_by text NOT NULL DEFAULT 'unknown'
    CHECK (linked_by IN ('unknown', 'email', 'explicit', 'signup'));

-- Existing identities take their link method from the audit log (the newest `identity.external.link`
-- or `identity.external.create` record for the same user and provider). Identities without such a
-- record stay `unknown` and are treated like `email` for platform users: a platform admin confirms
-- them with `POST /v1/users/{user_id}/identities` (see the upgrade note in CHANGELOG.md).
UPDATE axentra_user_identities i SET linked_by = a.method
FROM (
    SELECT DISTINCT ON (target_id, details ->> 'provider')
        target_id AS user_id,
        details ->> 'provider' AS provider,
        CASE
            WHEN action = 'identity.external.create' THEN 'explicit'
            WHEN details ->> 'how' = 'explicit' THEN 'explicit'
            WHEN details ->> 'how' = 'linked_by_email' THEN 'email'
            WHEN details ->> 'how' IN ('created', 'created_without_email') THEN 'signup'
        END AS method
    FROM axentra_audit_events
    WHERE action IN ('identity.external.link', 'identity.external.create')
      AND outcome = 'success' AND target_type = 'user'
    ORDER BY target_id, details ->> 'provider', occurred_at DESC, id DESC
) a
WHERE a.user_id = i.user_id AND a.provider = i.provider AND a.method IS NOT NULL;

-- A session started through an identity linked by email (or `unknown`) without the provider's
-- `link_platform_users_by_verified_email`. Such a session ends as soon as its user holds a platform
-- role, also when the role was granted after the sign-in (review finding: a session from before the
-- promotion, or a promotion between the link check and the session insert).
ALTER TABLE axentra_sessions
    ADD COLUMN via_email_link boolean NOT NULL DEFAULT false;
