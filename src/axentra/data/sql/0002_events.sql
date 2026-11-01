-- Axentra events module: persistent job queue, schedules, events (transactional outbox),
-- outgoing webhooks and deliveries. See docs/modules/EVENTS_AND_JOBS.md.
-- Every table carries product_id (and tenant_id where a row belongs to a tenant) and has
-- row-level security ENABLED and FORCED with the scope policy of migration 0001.
--
-- Stream positions: streamed rows (events, job status changes) get a position from
-- axentra_stream_seq only AFTER they committed, assigned by one assigner at a time (transaction
-- advisory lock; see axentra.events.streams). Positions therefore follow commit order and a reader
-- resuming after position N never misses a row that commits later.

CREATE SEQUENCE axentra_stream_seq;

CREATE TABLE axentra_jobs (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    tenant_id text,
    tenant_key text GENERATED ALWAYS AS (coalesce(tenant_id, '')) STORED,
    kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.:-]{0,99}$'),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'dead', 'cancelled')),
    priority integer NOT NULL DEFAULT 0 CHECK (priority BETWEEN -100 AND 100),
    run_after timestamptz NOT NULL DEFAULT now(),
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 100),
    backoff_base_seconds double precision NOT NULL DEFAULT 2,
    backoff_max_seconds double precision NOT NULL DEFAULT 3600,
    lease_until timestamptz,
    worker text,
    cancel_requested boolean NOT NULL DEFAULT false,
    last_error text,
    idempotency_key text CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 200),
    result jsonb,
    schedule_id text,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    change_pos bigint,
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
-- Idempotency keys are unique per product, tenant and kind for as long as the job row exists
-- (finished jobs are purged after observability.job_retention_days).
CREATE UNIQUE INDEX axentra_jobs_idempotency ON axentra_jobs (product_id, tenant_key, kind, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX axentra_jobs_claim ON axentra_jobs (priority DESC, run_after, id) WHERE status = 'queued';
CREATE INDEX axentra_jobs_lease ON axentra_jobs (lease_until) WHERE status = 'running';
CREATE INDEX axentra_jobs_list ON axentra_jobs (product_id, id DESC);
CREATE INDEX axentra_jobs_tenant ON axentra_jobs (product_id, tenant_id, id DESC);
CREATE INDEX axentra_jobs_changes ON axentra_jobs (product_id, change_pos);
CREATE INDEX axentra_jobs_unpositioned ON axentra_jobs (id) WHERE change_pos IS NULL;
CREATE INDEX axentra_jobs_finished ON axentra_jobs (finished_at) WHERE finished_at IS NOT NULL;
ALTER TABLE axentra_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_jobs USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- A visible change (status, attempts, cancellation, due time) clears the stream position (a new
-- one is assigned after commit) and bumps updated_at; lease renewals (heartbeats) do not.
CREATE FUNCTION axentra_jobs_touch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status OR NEW.attempts IS DISTINCT FROM OLD.attempts
        OR NEW.cancel_requested IS DISTINCT FROM OLD.cancel_requested
        OR NEW.run_after IS DISTINCT FROM OLD.run_after THEN
        NEW.change_pos := NULL;
        NEW.updated_at := clock_timestamp();
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER axentra_jobs_touch BEFORE UPDATE ON axentra_jobs FOR EACH ROW EXECUTE FUNCTION axentra_jobs_touch();

CREATE TABLE axentra_schedules (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    tenant_id text,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.:-]{0,99}$'),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    interval_seconds integer CHECK (interval_seconds IS NULL OR interval_seconds BETWEEN 10 AND 31622400),
    cron text,
    enabled boolean NOT NULL DEFAULT true,
    priority integer NOT NULL DEFAULT 0 CHECK (priority BETWEEN -100 AND 100),
    max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 100),
    next_run_at timestamptz,
    last_run_at timestamptz,
    last_job_id text,
    version integer NOT NULL DEFAULT 1,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((interval_seconds IS NULL) <> (cron IS NULL)),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE INDEX axentra_schedules_due ON axentra_schedules (next_run_at) WHERE enabled;
CREATE INDEX axentra_schedules_product ON axentra_schedules (product_id, id);
ALTER TABLE axentra_schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_schedules FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_schedules USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- Every slot of a schedule fires at most once (primary key), also when two schedulers overlap.
CREATE TABLE axentra_schedule_firings (
    schedule_id text NOT NULL REFERENCES axentra_schedules (id) ON DELETE CASCADE,
    slot timestamptz NOT NULL,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    tenant_id text,
    job_id text,
    fired_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (schedule_id, slot),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE INDEX axentra_schedule_firings_time ON axentra_schedule_firings (fired_at);
ALTER TABLE axentra_schedule_firings ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_schedule_firings FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_schedule_firings USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

CREATE TABLE axentra_events (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    tenant_id text,
    tenant_key text GENERATED ALWAYS AS (coalesce(tenant_id, '')) STORED,
    type text NOT NULL CHECK (type ~ '^[a-z][a-z0-9_.:-]{0,149}$'),
    data jsonb NOT NULL DEFAULT '{}'::jsonb,
    idempotency_key text CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 200),
    actor_kind text NOT NULL DEFAULT 'system',
    actor_id text NOT NULL DEFAULT '',
    request_id text,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    pos bigint,
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX axentra_events_idempotency ON axentra_events (product_id, tenant_key, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX axentra_events_list ON axentra_events (product_id, id DESC);
CREATE INDEX axentra_events_tenant ON axentra_events (product_id, tenant_id, id DESC);
CREATE INDEX axentra_events_stream ON axentra_events (product_id, pos);
CREATE INDEX axentra_events_unpositioned ON axentra_events (id) WHERE pos IS NULL;
CREATE INDEX axentra_events_time ON axentra_events (occurred_at);
ALTER TABLE axentra_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_events FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_events USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- Outgoing webhook endpoints of a product; tenant_id (optional) restricts the endpoint to the
-- events of one tenant. The signing secret is stored encrypted (SecretBox, context bound to the row).
CREATE TABLE axentra_webhook_endpoints (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    tenant_id text,
    url text NOT NULL CHECK (length(url) BETWEEN 8 AND 2000),
    description text NOT NULL DEFAULT '',
    event_types text[] NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    secret_enc text NOT NULL,
    previous_secret_enc text,
    previous_secret_expires_at timestamptz,
    version integer NOT NULL DEFAULT 1,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE INDEX axentra_webhook_endpoints_product ON axentra_webhook_endpoints (product_id, id);
ALTER TABLE axentra_webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_webhook_endpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_webhook_endpoints USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

CREATE TABLE axentra_webhook_deliveries (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    tenant_id text,
    endpoint_id text NOT NULL REFERENCES axentra_webhook_endpoints (id) ON DELETE CASCADE,
    event_id text REFERENCES axentra_events (id) ON DELETE CASCADE,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'succeeded', 'failed', 'dead')),
    attempts integer NOT NULL DEFAULT 0,
    response_code integer,
    response_body text,
    duration_ms integer,
    last_error text,
    next_attempt_at timestamptz,
    job_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX axentra_webhook_deliveries_once ON axentra_webhook_deliveries (endpoint_id, event_id)
    WHERE event_id IS NOT NULL;
CREATE INDEX axentra_webhook_deliveries_endpoint ON axentra_webhook_deliveries (endpoint_id, id DESC);
CREATE INDEX axentra_webhook_deliveries_time ON axentra_webhook_deliveries (created_at);
ALTER TABLE axentra_webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_webhook_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_webhook_deliveries USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));
