-- Axentra foundation schema: products, identity, tenancy, access, audit, records.
-- Row-level security (RLS) is enabled and FORCED on every product/tenant table; see
-- docs/architecture/SECURITY_MODEL.md. The application sets axentra.scope, axentra.product_id
-- and axentra.tenant_id per transaction (axentra.data.database.Database.transaction).

CREATE FUNCTION axentra_scope_allows(p text, t text) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT CASE current_setting('axentra.scope', true)
        WHEN 'platform' THEN true
        WHEN 'product' THEN p IS NOT NULL AND p = current_setting('axentra.product_id', true)
        WHEN 'tenant' THEN p IS NOT NULL AND p = current_setting('axentra.product_id', true)
            AND (t IS NULL OR t = current_setting('axentra.tenant_id', true))
        ELSE false
    END
$$;

CREATE TABLE axentra_products (
    id text PRIMARY KEY,
    slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    settings jsonb NOT NULL DEFAULT '{}'::jsonb,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE axentra_products ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_products FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_products USING (axentra_scope_allows(id, NULL)) WITH CHECK (axentra_scope_allows(id, NULL));

-- Users are global identities. A user sees and acts in a product only through memberships.
CREATE TABLE axentra_users (
    id text PRIMARY KEY,
    email text NOT NULL,
    name text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    password_hash text,
    locale text NOT NULL DEFAULT 'en',
    preferences jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);
CREATE UNIQUE INDEX axentra_users_email ON axentra_users (lower(email));

CREATE TABLE axentra_user_identities (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES axentra_users (id) ON DELETE CASCADE,
    provider text NOT NULL,
    subject text NOT NULL,
    email text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);
CREATE INDEX axentra_user_identities_user ON axentra_user_identities (user_id);

CREATE TABLE axentra_platform_roles (
    user_id text PRIMARY KEY REFERENCES axentra_users (id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('platform_admin', 'platform_viewer')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE axentra_sessions (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES axentra_users (id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    csrf_token text NOT NULL,
    auth_method text NOT NULL,
    ip text,
    user_agent text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX axentra_sessions_user ON axentra_sessions (user_id) WHERE revoked_at IS NULL;

CREATE TABLE axentra_login_states (
    state_hash text PRIMARY KEY,
    provider text NOT NULL,
    nonce text NOT NULL,
    code_verifier text NOT NULL,
    return_to text NOT NULL DEFAULT '/',
    invitation_token text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE TABLE axentra_setup_tokens (
    token_hash text PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);

-- Fixed-window counters for login throttling, shared by all API processes.
CREATE TABLE axentra_rate_limits (
    bucket text NOT NULL,
    window_start timestamptz NOT NULL,
    hits integer NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, window_start)
);

CREATE TABLE axentra_product_members (
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    user_id text NOT NULL REFERENCES axentra_users (id) ON DELETE CASCADE,
    role text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (product_id, user_id)
);
CREATE INDEX axentra_product_members_user ON axentra_product_members (user_id);
ALTER TABLE axentra_product_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_product_members FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_product_members USING (axentra_scope_allows(product_id, NULL)) WITH CHECK (axentra_scope_allows(product_id, NULL));

CREATE TABLE axentra_tenants (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    slug text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    settings jsonb NOT NULL DEFAULT '{}'::jsonb,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (product_id, slug),
    UNIQUE (product_id, id)
);
ALTER TABLE axentra_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_tenants USING (axentra_scope_allows(product_id, id)) WITH CHECK (axentra_scope_allows(product_id, id));

CREATE TABLE axentra_memberships (
    id text PRIMARY KEY,
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    user_id text NOT NULL REFERENCES axentra_users (id) ON DELETE CASCADE,
    role text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE,
    UNIQUE (tenant_id, user_id)
);
CREATE INDEX axentra_memberships_user ON axentra_memberships (user_id);
ALTER TABLE axentra_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_memberships USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

CREATE TABLE axentra_invitations (
    id text PRIMARY KEY,
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    email text NOT NULL,
    role text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    invited_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    accepted_by text,
    revoked_at timestamptz,
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE INDEX axentra_invitations_tenant ON axentra_invitations (product_id, tenant_id);
ALTER TABLE axentra_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_invitations USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- Custom roles of a product (built-in roles live in code, axentra.access.permissions).
CREATE TABLE axentra_roles (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    key text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]{1,40}$'),
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    scope text NOT NULL CHECK (scope IN ('product', 'tenant')),
    permissions text[] NOT NULL DEFAULT '{}',
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (product_id, key)
);
ALTER TABLE axentra_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_roles USING (axentra_scope_allows(product_id, NULL)) WITH CHECK (axentra_scope_allows(product_id, NULL));

CREATE TABLE axentra_api_keys (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    tenant_id text,
    name text NOT NULL,
    secret_hash text NOT NULL,
    permissions text[] NOT NULL DEFAULT '{}',
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    expires_at timestamptz,
    revoked_at timestamptz,
    replaces text,
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE INDEX axentra_api_keys_product ON axentra_api_keys (product_id);
ALTER TABLE axentra_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_api_keys USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- Append-only audit trail. Platform events have no product.
CREATE TABLE axentra_audit_events (
    id text PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    product_id text,
    tenant_id text,
    actor_kind text NOT NULL,
    actor_id text NOT NULL,
    actor_display text NOT NULL DEFAULT '',
    action text NOT NULL,
    target_type text NOT NULL DEFAULT '',
    target_id text NOT NULL DEFAULT '',
    outcome text NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'denied', 'failure')),
    request_id text,
    ip text,
    details jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX axentra_audit_events_time ON axentra_audit_events (occurred_at DESC, id DESC);
CREATE INDEX axentra_audit_events_product ON axentra_audit_events (product_id, occurred_at DESC);
CREATE INDEX axentra_audit_events_action ON axentra_audit_events (action);
ALTER TABLE axentra_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_audit_events USING (axentra_scope_allows(product_id, tenant_id) OR (product_id IS NULL AND current_setting('axentra.scope', true) = 'platform'))
    WITH CHECK (axentra_scope_allows(product_id, tenant_id) OR product_id IS NULL);

-- Generic tenant-owned JSON records for product data that does not need its own table.
CREATE TABLE axentra_records (
    id text PRIMARY KEY,
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    collection text NOT NULL CHECK (collection ~ '^[a-z][a-z0-9_]{0,62}$'),
    data jsonb NOT NULL,
    version integer NOT NULL DEFAULT 1,
    created_by text,
    updated_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE INDEX axentra_records_list ON axentra_records (product_id, tenant_id, collection, id);
CREATE INDEX axentra_records_data ON axentra_records USING gin (data jsonb_path_ops);
ALTER TABLE axentra_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_records FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_records USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));
