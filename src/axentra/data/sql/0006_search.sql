-- Search: a tenant-scoped full-text index. Products push documents (kind + ref_id identify the
-- source object, e.g. kind 'invoice', ref_id 'inv_123'); the index is a derived copy, never the
-- source of truth. The tsvector is a generated column over title (weight A) and body (weight B)
-- in the document's text search configuration (search.language, default 'simple').
-- See docs/modules/SEARCH.md.

CREATE TABLE axentra_search_documents (
    id text PRIMARY KEY,
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.-]{0,62}$'),
    ref_id text NOT NULL CHECK (ref_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,199}$'),
    title text NOT NULL DEFAULT '' CHECK (length(title) <= 1000),
    body text NOT NULL DEFAULT '' CHECK (length(body) <= 1000000),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    language regconfig NOT NULL DEFAULT 'simple',
    search_vector tsvector GENERATED ALWAYS AS (
        setweight(to_tsvector(language, title), 'A') || setweight(to_tsvector(language, body), 'B')
    ) STORED,
    version integer NOT NULL DEFAULT 1,
    created_by text,
    updated_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE,
    UNIQUE (product_id, tenant_id, kind, ref_id)
);
CREATE INDEX axentra_search_documents_vector ON axentra_search_documents USING gin (search_vector);
ALTER TABLE axentra_search_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_search_documents FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_search_documents USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));
