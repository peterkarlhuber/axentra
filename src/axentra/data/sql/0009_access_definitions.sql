-- Versioned access definitions (docs/architecture/SECURITY_MODEL.md, "Versioned access definitions").
-- One row per product: the revision and content hash of the permission and role definitions an embedding
-- product last applied from code (axentra.access.definitions). A process applies its definitions only when
-- its revision is newer than the stored one; an equal revision with equal content is a no-op, an older one is
-- refused (an old process never downgrades), and an equal revision with other content is a conflict.
-- `roles` lists the role keys the definitions manage (they cannot be changed or deleted over the API).
--
-- Also: an embedding product may carry its own context through an OIDC login (encrypted, like the nonce).
--
-- Does not depend on migrations 0007 or 0008 beyond the tables of 0001.

CREATE TABLE axentra_access_definitions (
    product_id text PRIMARY KEY REFERENCES axentra_products (id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision >= 1),
    content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    roles text[] NOT NULL DEFAULT '{}',
    applied_by text NOT NULL DEFAULT '' CHECK (length(applied_by) <= 200),
    applied_at timestamptz NOT NULL DEFAULT now(),
    version integer NOT NULL DEFAULT 1
);
ALTER TABLE axentra_access_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_access_definitions FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_access_definitions USING (axentra_scope_allows(product_id, NULL)) WITH CHECK (axentra_scope_allows(product_id, NULL));

ALTER TABLE axentra_login_states ADD COLUMN host_context text;
