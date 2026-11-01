-- Usage metering (meters, idempotent events, aggregated counters, quotas, reservations) and
-- billing (plans with prices and entitlements, tenant subscriptions, entitlement overrides,
-- processed provider webhook events). Axentra never stores card data.
-- RLS: every table is ENABLED + FORCED with the axentra_scope_allows policy (see 0001).

-- == Usage ======================================================================================

CREATE TABLE axentra_usage_meters (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    key text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_.]{0,62}$'),
    name text NOT NULL DEFAULT '' CHECK (length(name) <= 200),
    unit text NOT NULL DEFAULT '' CHECK (length(unit) <= 40),
    aggregation text NOT NULL DEFAULT 'sum' CHECK (aggregation IN ('sum', 'max', 'last')),
    reset_period text NOT NULL DEFAULT 'month' CHECK (reset_period IN ('none', 'day', 'month', 'billing_period')),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    default_limit numeric CHECK (default_limit IS NULL OR default_limit >= 0),
    default_enforcement text NOT NULL DEFAULT 'hard' CHECK (default_enforcement IN ('hard', 'soft')),
    active boolean NOT NULL DEFAULT true,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (product_id, key),
    UNIQUE (product_id, id)
);
ALTER TABLE axentra_usage_meters ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_usage_meters FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_usage_meters USING (axentra_scope_allows(product_id, NULL)) WITH CHECK (axentra_scope_allows(product_id, NULL));

-- Append-only usage events. The idempotency key is unique per tenant; request_hash detects a
-- reused key with a different body.
CREATE TABLE axentra_usage_events (
    id text PRIMARY KEY,
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    meter_id text NOT NULL,
    quantity numeric NOT NULL CHECK (quantity >= 0),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 200),
    request_hash text NOT NULL,
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    period_start timestamptz NOT NULL,
    properties jsonb NOT NULL DEFAULT '{}'::jsonb,
    reservation_id text,
    actor_id text NOT NULL DEFAULT '',
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE,
    FOREIGN KEY (product_id, meter_id) REFERENCES axentra_usage_meters (product_id, id),
    UNIQUE (product_id, tenant_id, idempotency_key)
);
CREATE INDEX axentra_usage_events_list ON axentra_usage_events (product_id, tenant_id, occurred_at DESC, id DESC);
CREATE INDEX axentra_usage_events_meter ON axentra_usage_events (product_id, meter_id);
ALTER TABLE axentra_usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_usage_events FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_usage_events USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- Aggregates, updated in the same transaction as the event. granularity 'period' rows follow the
-- meter's reset period (and serve as the lock row for quota checks); 'day' rows feed time series.
CREATE TABLE axentra_usage_counters (
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    meter_id text NOT NULL,
    granularity text NOT NULL CHECK (granularity IN ('period', 'day')),
    period_start timestamptz NOT NULL,
    period_end timestamptz,
    value numeric NOT NULL DEFAULT 0,
    event_count bigint NOT NULL DEFAULT 0,
    last_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (product_id, tenant_id, meter_id, granularity, period_start),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE,
    FOREIGN KEY (product_id, meter_id) REFERENCES axentra_usage_meters (product_id, id) ON DELETE CASCADE
);
CREATE INDEX axentra_usage_counters_product ON axentra_usage_counters (product_id, meter_id, granularity, period_start);
ALTER TABLE axentra_usage_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_usage_counters FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_usage_counters USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- Per-tenant quota overrides. Without a row the limit comes from the plan entitlements (billing)
-- or the meter default. limit_value NULL = unlimited.
CREATE TABLE axentra_usage_quotas (
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    meter_id text NOT NULL,
    limit_value numeric CHECK (limit_value IS NULL OR limit_value >= 0),
    enforcement text NOT NULL DEFAULT 'hard' CHECK (enforcement IN ('hard', 'soft')),
    version integer NOT NULL DEFAULT 1,
    updated_by text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (product_id, tenant_id, meter_id),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE,
    FOREIGN KEY (product_id, meter_id) REFERENCES axentra_usage_meters (product_id, id) ON DELETE CASCADE
);
ALTER TABLE axentra_usage_quotas ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_usage_quotas FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_usage_quotas USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

CREATE TABLE axentra_usage_reservations (
    id text PRIMARY KEY,
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    meter_id text NOT NULL,
    quantity numeric NOT NULL CHECK (quantity > 0),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'committed', 'released', 'expired')),
    period_start timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    idempotency_key text,
    request_hash text,
    event_id text,
    committed_quantity numeric,
    created_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE,
    FOREIGN KEY (product_id, meter_id) REFERENCES axentra_usage_meters (product_id, id) ON DELETE CASCADE,
    UNIQUE (product_id, tenant_id, idempotency_key)
);
CREATE INDEX axentra_usage_reservations_active ON axentra_usage_reservations (product_id, tenant_id, meter_id, period_start)
    WHERE status = 'active';
CREATE INDEX axentra_usage_reservations_expiry ON axentra_usage_reservations (expires_at) WHERE status = 'active';
ALTER TABLE axentra_usage_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_usage_reservations FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_usage_reservations USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- == Billing ====================================================================================

-- prices: [{"id": "prc_...", "amount_minor": 900, "currency": "EUR", "interval": "month",
--           "provider_price_id": "price_..."}]; entitlements: {"feature.x": true, "limit.api_calls": 10000}
CREATE TABLE axentra_billing_plans (
    id text PRIMARY KEY,
    product_id text NOT NULL REFERENCES axentra_products (id) ON DELETE CASCADE,
    key text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_-]{0,62}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    active boolean NOT NULL DEFAULT true,
    trial_days integer NOT NULL DEFAULT 0 CHECK (trial_days BETWEEN 0 AND 365),
    prices jsonb NOT NULL DEFAULT '[]'::jsonb,
    entitlements jsonb NOT NULL DEFAULT '{}'::jsonb,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (product_id, key),
    UNIQUE (product_id, id)
);
ALTER TABLE axentra_billing_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_billing_plans FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_billing_plans USING (axentra_scope_allows(product_id, NULL)) WITH CHECK (axentra_scope_allows(product_id, NULL));

CREATE TABLE axentra_billing_subscriptions (
    id text PRIMARY KEY,
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    plan_id text NOT NULL,
    price jsonb,
    status text NOT NULL CHECK (status IN ('trialing', 'active', 'past_due', 'canceled', 'incomplete')),
    period_anchor timestamptz NOT NULL,
    current_period_start timestamptz NOT NULL,
    current_period_end timestamptz NOT NULL,
    trial_end timestamptz,
    cancel_at_period_end boolean NOT NULL DEFAULT false,
    canceled_at timestamptz,
    provider text NOT NULL CHECK (provider IN ('manual', 'fake', 'stripe')),
    provider_customer_id text,
    provider_subscription_id text,
    provider_checkout_id text,
    last_provider_event_at timestamptz,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE,
    FOREIGN KEY (product_id, plan_id) REFERENCES axentra_billing_plans (product_id, id)
);
-- At most one subscription per tenant that is not canceled.
CREATE UNIQUE INDEX axentra_billing_subscriptions_current ON axentra_billing_subscriptions (product_id, tenant_id)
    WHERE status <> 'canceled';
CREATE UNIQUE INDEX axentra_billing_subscriptions_provider_sub ON axentra_billing_subscriptions (provider, provider_subscription_id)
    WHERE provider_subscription_id IS NOT NULL;
CREATE UNIQUE INDEX axentra_billing_subscriptions_provider_checkout ON axentra_billing_subscriptions (provider, provider_checkout_id)
    WHERE provider_checkout_id IS NOT NULL;
CREATE INDEX axentra_billing_subscriptions_list ON axentra_billing_subscriptions (product_id, created_at DESC, id DESC);
ALTER TABLE axentra_billing_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_billing_subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_billing_subscriptions USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

CREATE TABLE axentra_billing_overrides (
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    entitlements jsonb NOT NULL DEFAULT '{}'::jsonb,
    version integer NOT NULL DEFAULT 1,
    updated_by text,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (product_id, tenant_id),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
ALTER TABLE axentra_billing_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_billing_overrides FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_billing_overrides USING (axentra_scope_allows(product_id, tenant_id)) WITH CHECK (axentra_scope_allows(product_id, tenant_id));

-- Processed provider webhook events (replay protection). Unmatched events have no product.
CREATE TABLE axentra_billing_webhook_events (
    provider text NOT NULL,
    event_id text NOT NULL CHECK (length(event_id) BETWEEN 1 AND 255),
    event_type text NOT NULL,
    provider_created_at timestamptz,
    product_id text REFERENCES axentra_products (id) ON DELETE CASCADE,
    tenant_id text,
    subscription_id text,
    outcome text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, event_id),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE
);
CREATE INDEX axentra_billing_webhook_events_product ON axentra_billing_webhook_events (product_id, received_at DESC);
ALTER TABLE axentra_billing_webhook_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE axentra_billing_webhook_events FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON axentra_billing_webhook_events
    USING (axentra_scope_allows(product_id, tenant_id) OR (product_id IS NULL AND current_setting('axentra.scope', true) = 'platform'))
    WITH CHECK (axentra_scope_allows(product_id, tenant_id) OR (product_id IS NULL AND current_setting('axentra.scope', true) = 'platform'));
