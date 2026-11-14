-- How an external identity got linked to its user (owner decision I5, 2026-11-14).
--
-- A user with a platform role signs in through an identity provider only with an identity that a
-- platform admin linked explicitly (`explicit`) or that created the account (`signup`). An identity
-- linked by verified email (`email`) stops working when the user gets a platform role, so a provider
-- that is wrong about an address cannot reach a platform account, also not by an older link.
ALTER TABLE axentra_user_identities
    ADD COLUMN linked_by text NOT NULL DEFAULT 'unknown'
    CHECK (linked_by IN ('unknown', 'email', 'explicit', 'signup'));

-- Existing identities take their link method from the audit log (`identity.external.link` and
-- `identity.external.create` records for the same user and provider). The records name no subject, so
-- the method is taken only where the user has exactly one identity of that provider and every record
-- agrees; anything else stays `unknown`, which counts like `email` for platform users: a platform
-- admin confirms such an identity with `POST /v1/users/{user_id}/identities` (upgrade note in
-- CHANGELOG.md). The audit table forces row-level security for its owner too, so the platform scope
-- is set for this transaction.
SELECT set_config('axentra.scope', 'platform', true);

UPDATE axentra_user_identities i SET linked_by = a.method
FROM (
    SELECT user_id, provider, min(method) AS method
    FROM (
        SELECT
            target_id AS user_id,
            details ->> 'provider' AS provider,
            CASE
                WHEN action = 'identity.external.create' THEN 'explicit'
                WHEN details ->> 'how' = 'explicit' THEN 'explicit'
                WHEN details ->> 'how' = 'linked_by_email' THEN 'email'
                WHEN details ->> 'how' IN ('created', 'created_without_email') THEN 'signup'
                ELSE 'unknown'
            END AS method
        FROM axentra_audit_events
        WHERE action IN ('identity.external.link', 'identity.external.create')
          AND outcome = 'success' AND target_type = 'user'
    ) records
    GROUP BY user_id, provider
    HAVING count(DISTINCT method) = 1
) a
WHERE a.user_id = i.user_id AND a.provider = i.provider AND a.method <> 'unknown'
  AND (SELECT count(*) FROM axentra_user_identities o
       WHERE o.user_id = i.user_id AND o.provider = i.provider) = 1;

-- A session started through an identity linked by email (or `unknown`) without the provider's
-- `link_platform_users_by_verified_email`. Such a session ends as soon as its user holds a platform
-- role, also when the role was granted after the sign-in (review finding: a session from before the
-- promotion, or a promotion between the link check and the session insert).
ALTER TABLE axentra_sessions
    ADD COLUMN via_email_link boolean NOT NULL DEFAULT false;
