-- Notifications: templates, the outbox (messages), the local development mailbox and
-- per-user preferences. Rendered content is stored encrypted (SecretBox, bound to table/row/field)
-- and erased after notify.content_retention_days; recipient addresses are personal data and are
-- deleted with the message after notify.message_retention_days (see docs/modules/NOTIFY.md).

CREATE TABLE axentra_notify_templates (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    key text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_.-]{1,62}$'),
    channel text NOT NULL DEFAULT 'email' CHECK (channel IN ('email', 'sms', 'push')),
    category text NOT NULL DEFAULT 'transactional' CHECK (category ~ '^[a-z][a-z0-9_]{1,40}$'),
    name text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    variables text[] NOT NULL DEFAULT '{}',
    sample_data jsonb NOT NULL DEFAULT '{}'::jsonb,
    variants jsonb NOT NULL,
    sensitive boolean NOT NULL DEFAULT false,
    version integer NOT NULL DEFAULT 1,
    created_by text,
    updated_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (product_id, key)
);
ALTER TABLE axentra_notify_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_notify_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_notify_templates USING (axentra_scope_allows(product_id, NULL)) WITH CHECK (axentra_scope_allows(product_id, NULL));

CREATE TABLE axentra_notify_messages (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    tenant_id text,
    template_key text NOT NULL,
    template_version integer NOT NULL,
    channel text NOT NULL DEFAULT 'email' CHECK (channel IN ('email', 'sms', 'push')),
    category text NOT NULL,
    recipient text NOT NULL,
    recipient_user_id text REFERENCES axentra_users (id) ON DELETE SET NULL,
    locale text NOT NULL,
    subject_enc text,
    body_text_enc text,
    body_html_enc text,
    sensitive boolean NOT NULL DEFAULT false,
    status text NOT NULL CHECK (status IN ('queued', 'sending', 'sent', 'failed', 'suppressed')),
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    lease_until timestamptz,
    claim_token text,
    last_error text,
    provider text,
    provider_message_id text,
    idempotency_key text,
    request_hash text,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz,
    content_purged_at timestamptz,
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE,
    UNIQUE (product_id, idempotency_key)
);
CREATE INDEX axentra_notify_messages_list ON axentra_notify_messages (product_id, created_at DESC, id DESC);
CREATE INDEX axentra_notify_messages_tenant ON axentra_notify_messages (product_id, tenant_id, created_at DESC);
CREATE INDEX axentra_notify_messages_due ON axentra_notify_messages (next_attempt_at) WHERE status = 'queued';
CREATE INDEX axentra_notify_messages_lease ON axentra_notify_messages (lease_until) WHERE status = 'sending';
ALTER TABLE axentra_notify_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_notify_messages FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_notify_messages USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- What the local (development) provider "delivered". Never used by the SMTP provider.
CREATE TABLE axentra_notify_mailbox (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    tenant_id text,
    message_id text NOT NULL,
    sender text NOT NULL,
    recipient text NOT NULL,
    subject_enc text NOT NULL,
    body_text_enc text NOT NULL,
    body_html_enc text,
    provider_message_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE INDEX axentra_notify_mailbox_list ON axentra_notify_mailbox (product_id, created_at DESC, id DESC);
ALTER TABLE axentra_notify_mailbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_notify_mailbox FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_notify_mailbox USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- Opt-outs per user and product (tenant_id NULL) or per user, product and tenant.
CREATE TABLE axentra_notify_preferences (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    tenant_id text,
    user_id text NOT NULL REFERENCES axentra_users (id) ON DELETE CASCADE,
    opted_out text[] NOT NULL DEFAULT '{}',
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX axentra_notify_preferences_key ON axentra_notify_preferences (product_id, user_id, coalesce(tenant_id, ''));
ALTER TABLE axentra_notify_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_notify_preferences FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_notify_preferences USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));
