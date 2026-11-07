-- axentra:no-transaction
-- Record lists sorted by time (sort=created_at / updated_at, ascending or descending) read one
-- collection of one tenant in time order. Without these indexes PostgreSQL sorted every record of
-- the collection before returning the first page. Built CONCURRENTLY so existing installations keep
-- writing records during the upgrade; IF NOT EXISTS makes a rerun after an interruption safe (an
-- interrupted concurrent build can leave an INVALID index behind: drop it and run `axentra migrate`
-- again, see docs/architecture/DATA.md).
CREATE INDEX CONCURRENTLY IF NOT EXISTS axentra_records_created
    ON axentra_records (product_id, tenant_id, collection, created_at, id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS axentra_records_updated
    ON axentra_records (product_id, tenant_id, collection, updated_at, id);
