-- Tenant scope may READ product-level rows (tenant_id IS NULL) of its product, but never WRITE them
-- (security review finding SR-02). Before this migration the single `scope` policy of each table used
-- axentra_scope_allows in USING and WITH CHECK, so a tenant-bound transaction could insert, update,
-- re-home (tenant_id NULL -> own tenant) or delete product-level rows such as product-wide API keys,
-- custom roles, schedules or webhooks.
--
-- axentra_scope_allows (read side) is unchanged. axentra_scope_allows_write is the write side: in
-- tenant scope it requires t = the current tenant (NULL is refused); platform and product scope are
-- unchanged. Every table that uses axentra_scope_allows gets:
--   * the `scope` policy's WITH CHECK switched to the write function (INSERT, and the new row of an
--     UPDATE), and
--   * two RESTRICTIVE policies, `scope_update` and `scope_delete`, whose USING is the write function,
--     so UPDATE and DELETE (and SELECT ... FOR UPDATE / FOR SHARE) in tenant scope only reach rows of
--     the current tenant. Restrictive policies are AND-ed with `scope`; SELECT is not affected.
-- Tables that store only product-level rows pass NULL as the tenant (products, product members,
-- roles, meters, plans, templates, product permissions, access definitions): they are read-only in
-- tenant scope from now on.

CREATE FUNCTION axentra_scope_allows_write(p text, t text) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT CASE current_setting('axentra.scope', true)
        WHEN 'platform' THEN true
        WHEN 'product' THEN p IS NOT NULL AND p = current_setting('axentra.product_id', true)
        WHEN 'tenant' THEN p IS NOT NULL AND p = current_setting('axentra.product_id', true)
            AND t IS NOT NULL AND t = current_setting('axentra.tenant_id', true)
        ELSE false
    END
$$;

DO $$
DECLARE
    -- table, product expression, tenant expression (as in the table's `scope` policy)
    spec text[];
    specs text[][] := ARRAY[
        ['axentra_products', 'id', 'NULL'],
        ['axentra_product_members', 'product_id', 'NULL'],
        ['axentra_tenants', 'product_id', 'id'],
        ['axentra_memberships', 'product_id', 'tenant_id'],
        ['axentra_invitations', 'product_id', 'tenant_id'],
        ['axentra_roles', 'product_id', 'NULL'],
        ['axentra_api_keys', 'product_id', 'tenant_id'],
        ['axentra_records', 'product_id', 'tenant_id'],
        ['axentra_jobs', 'product_id', 'tenant_id'],
        ['axentra_schedules', 'product_id', 'tenant_id'],
        ['axentra_schedule_firings', 'product_id', 'tenant_id'],
        ['axentra_events', 'product_id', 'tenant_id'],
        ['axentra_webhook_endpoints', 'product_id', 'tenant_id'],
        ['axentra_webhook_deliveries', 'product_id', 'tenant_id'],
        ['axentra_files', 'product_id', 'tenant_id'],
        ['axentra_storage_quotas', 'product_id', 'tenant_id'],
        ['axentra_storage_usage', 'product_id', 'tenant_id'],
        ['axentra_usage_meters', 'product_id', 'NULL'],
        ['axentra_usage_events', 'product_id', 'tenant_id'],
        ['axentra_usage_counters', 'product_id', 'tenant_id'],
        ['axentra_usage_quotas', 'product_id', 'tenant_id'],
        ['axentra_usage_reservations', 'product_id', 'tenant_id'],
        ['axentra_billing_plans', 'product_id', 'NULL'],
        ['axentra_billing_subscriptions', 'product_id', 'tenant_id'],
        ['axentra_billing_overrides', 'product_id', 'tenant_id'],
        ['axentra_notify_templates', 'product_id', 'NULL'],
        ['axentra_notify_messages', 'product_id', 'tenant_id'],
        ['axentra_notify_mailbox', 'product_id', 'tenant_id'],
        ['axentra_notify_preferences', 'product_id', 'tenant_id'],
        ['axentra_search_documents', 'product_id', 'tenant_id'],
        ['axentra_product_permissions', 'product_id', 'NULL'],
        ['axentra_access_definitions', 'product_id', 'NULL']
    ];
    w text;
BEGIN
    FOREACH spec SLICE 1 IN ARRAY specs LOOP
        w := format('axentra_scope_allows_write(%s, %s)', spec[2], spec[3]);
        EXECUTE format('ALTER POLICY scope ON %I WITH CHECK (%s)', spec[1], w);
        EXECUTE format('CREATE POLICY scope_update ON %I AS RESTRICTIVE FOR UPDATE USING (%s)', spec[1], w);
        EXECUTE format('CREATE POLICY scope_delete ON %I AS RESTRICTIVE FOR DELETE USING (%s)', spec[1], w);
    END LOOP;
END
$$;

-- Audit events: platform events (product_id NULL) may still be appended from any scope (documented);
-- product-level events (tenant_id NULL) only from product or platform scope.
ALTER POLICY scope ON axentra_audit_events
    WITH CHECK (axentra_scope_allows_write(product_id, tenant_id) OR product_id IS NULL);
CREATE POLICY scope_update ON axentra_audit_events AS RESTRICTIVE FOR UPDATE
    USING (axentra_scope_allows_write(product_id, tenant_id) OR (product_id IS NULL AND current_setting('axentra.scope', true) = 'platform'));
CREATE POLICY scope_delete ON axentra_audit_events AS RESTRICTIVE FOR DELETE
    USING (axentra_scope_allows_write(product_id, tenant_id) OR (product_id IS NULL AND current_setting('axentra.scope', true) = 'platform'));

-- Billing provider webhook events: unchanged shape, write side as above.
ALTER POLICY scope ON axentra_billing_webhook_events
    WITH CHECK (axentra_scope_allows_write(product_id, tenant_id) OR (product_id IS NULL AND current_setting('axentra.scope', true) = 'platform'));
CREATE POLICY scope_update ON axentra_billing_webhook_events AS RESTRICTIVE FOR UPDATE
    USING (axentra_scope_allows_write(product_id, tenant_id) OR (product_id IS NULL AND current_setting('axentra.scope', true) = 'platform'));
CREATE POLICY scope_delete ON axentra_billing_webhook_events AS RESTRICTIVE FOR DELETE
    USING (axentra_scope_allows_write(product_id, tenant_id) OR (product_id IS NULL AND current_setting('axentra.scope', true) = 'platform'));
