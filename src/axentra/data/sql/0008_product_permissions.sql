-- Product-defined permissions (docs/architecture/SECURITY_MODEL.md, "Product-defined permissions").
-- One row per product and name. Embedding products register definitions in process and Axentra
-- mirrors them here at start (declared_by = 'code'); other products declare them over the API
-- (declared_by = 'api'). Rows are never deleted while the product exists: a permission that is no
-- longer declared is retired (retired_at), and a retired name grants nothing wherever it is still
-- stored (custom roles, API keys).
--
-- Also: files stored inert keep the type they would have had (storage content-type policy,
-- docs/modules/STORAGE.md).
--
-- Does not depend on migration 0007.

CREATE TABLE axentra_product_permissions (
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    name text NOT NULL CHECK (
        length(name) <= 128 AND name ~ '^[a-z][a-z0-9_-]*\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*:[a-z][a-z0-9_]*$'
    ),
    scope text NOT NULL CHECK (scope IN ('product', 'tenant')),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    read_like boolean NOT NULL DEFAULT false,
    default_roles text[] NOT NULL DEFAULT '{}',
    declared_by text NOT NULL CHECK (declared_by IN ('code', 'api')),
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    PRIMARY KEY (product_id, name)
);
ALTER TABLE axentra_product_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_product_permissions FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_product_permissions USING (axentra_scope_allows(product_id, NULL)) WITH CHECK (axentra_scope_allows(product_id, NULL));

ALTER TABLE axentra_files ADD COLUMN stored_inert boolean NOT NULL DEFAULT false;
ALTER TABLE axentra_files ADD COLUMN original_content_type text;
