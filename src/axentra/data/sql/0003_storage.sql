-- Storage module: file metadata, per-tenant quotas and usage counters.
-- File bytes live in the configured object storage backend (local directory or S3) under a key
-- derived only from ids: <product_id>/<tenant_id>/<file_id>. RLS is enabled and FORCED on every
-- table, like in 0001.

CREATE TABLE axentra_files (
    id text PRIMARY KEY,
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    content_type text NOT NULL,
    size bigint NOT NULL DEFAULT 0 CHECK (size >= 0),
    sha256 text CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
    storage_key text NOT NULL UNIQUE,
    backend text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'deleted')),
    version integer NOT NULL DEFAULT 1,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    deleted_at timestamptz,
    -- Set once the backend confirmed the object deletion; NULL on deleted rows means "retry".
    object_deleted_at timestamptz,
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE INDEX axentra_files_list ON axentra_files (product_id, tenant_id, created_at, id) WHERE status = 'active';
CREATE INDEX axentra_files_expiry ON axentra_files (expires_at) WHERE status = 'active' AND expires_at IS NOT NULL;
CREATE INDEX axentra_files_pending ON axentra_files (created_at) WHERE status = 'pending';
CREATE INDEX axentra_files_unpurged ON axentra_files (deleted_at) WHERE status = 'deleted' AND object_deleted_at IS NULL;
ALTER TABLE axentra_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_files FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_files USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- Per-tenant quota overrides. NULL means "inherit" (product settings storage.quota_bytes /
-- storage.quota_files, then the installation default, then unlimited).
CREATE TABLE axentra_storage_quotas (
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    quota_bytes bigint CHECK (quota_bytes IS NULL OR quota_bytes >= 0),
    quota_files integer CHECK (quota_files IS NULL OR quota_files >= 0),
    version integer NOT NULL DEFAULT 1,
    updated_by text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (product_id, tenant_id),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
ALTER TABLE axentra_storage_quotas ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_storage_quotas FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_storage_quotas USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- Usage counters of active files. Uploads lock this row (SELECT ... FOR UPDATE) while checking the
-- quota, so concurrent uploads of one tenant serialize on it and cannot overshoot the quota.
CREATE TABLE axentra_storage_usage (
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    bytes_used bigint NOT NULL DEFAULT 0 CHECK (bytes_used >= 0),
    files_used integer NOT NULL DEFAULT 0 CHECK (files_used >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (product_id, tenant_id),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
ALTER TABLE axentra_storage_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_storage_usage FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_storage_usage USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));
