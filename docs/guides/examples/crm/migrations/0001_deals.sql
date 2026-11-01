-- Example product migration (namespace "crm"), used by docs/guides/PRODUCT_TABLES.md and
-- exercised by tests/integration/test_product_tables_guide.py.
-- Prefix every object with the product namespace; never touch axentra_* objects except to
-- reference axentra_tenants / axentra_products and to call axentra_scope_allows().

CREATE TABLE crm_deals (
    id text PRIMARY KEY,
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    stage text NOT NULL DEFAULT 'open' CHECK (stage IN ('open', 'won', 'lost')),
    amount_cents bigint NOT NULL DEFAULT 0 CHECK (amount_cents >= 0),
    version integer NOT NULL DEFAULT 1,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    -- Deleting the tenant (or the product) deletes its deals.
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
-- Every list query filters by product and tenant first; keyset pagination uses id.
CREATE INDEX crm_deals_list ON crm_deals (product_id, tenant_id, id);
CREATE INDEX crm_deals_stage ON crm_deals (product_id, tenant_id, stage);

-- Row-level security: rows are visible and writable only inside their product/tenant scope.
-- FORCE also applies the policy to the table owner (the migration role).
ALTER TABLE crm_deals ENABLE ROW LEVEL SECURITY;
ALTER TABLE crm_deals FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON crm_deals
    USING (axentra_scope_allows(product_id, tenant_id))
    WITH CHECK (axentra_scope_allows(product_id, tenant_id));
