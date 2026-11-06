-- Product-level invitations for operators: an invitation with tenant_id NULL invites an email
-- address to the product team (axentra_product_members) with a product role. Before, a product
-- owner could only add operators who already had an account the owner could see.
--
-- tenant_id NULL rows are product-level rows: the existing `scope` policies (axentra_scope_allows,
-- write side axentra_scope_allows_write from 0011) already treat them like every other
-- product-level row (readable in tenant scope of the same product, writable from product or
-- platform scope only). The composite foreign key to axentra_tenants is not checked for NULL
-- tenants, so product rows get their own key to the product.

ALTER TABLE axentra_invitations ALTER COLUMN tenant_id DROP NOT NULL;
ALTER TABLE axentra_invitations ADD CONSTRAINT axentra_invitations_product_fk
    FOREIGN KEY (product_id) REFERENCES axentra_products (id) ON DELETE CASCADE;
CREATE INDEX axentra_invitations_product_open ON axentra_invitations (product_id, lower(email))
    WHERE tenant_id IS NULL AND accepted_at IS NULL AND revoked_at IS NULL;
