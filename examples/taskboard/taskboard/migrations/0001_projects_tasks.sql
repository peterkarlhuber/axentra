-- Taskboard schema, migration namespace "taskboard" (registered with ax.register_migrations).
-- Every object is prefixed with taskboard_; Axentra's tables are only referenced, never altered.
-- Pattern: docs/guides/PRODUCT_TABLES.md (product_id + tenant_id, FK to axentra_tenants with
-- ON DELETE CASCADE, ENABLE + FORCE row-level security with axentra_scope_allows()).

CREATE TABLE taskboard_projects (
    id text PRIMARY KEY,
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 5000),
    archived boolean NOT NULL DEFAULT false,
    version integer NOT NULL DEFAULT 1,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    -- Deleting the workspace (tenant) or the product deletes its projects.
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE,
    -- Target of the tasks' composite foreign key (a task's project is always in the same tenant).
    UNIQUE (product_id, tenant_id, id)
);
CREATE INDEX taskboard_projects_list ON taskboard_projects (product_id, tenant_id, id);

CREATE TABLE taskboard_tasks (
    id text PRIMARY KEY,
    product_id text NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 20000),
    status text NOT NULL DEFAULT 'todo' CHECK (status IN ('todo', 'doing', 'done')),
    assignee_id text,
    due_date date,
    -- Optional client-supplied Idempotency-Key of the create request (unique per tenant).
    idempotency_key text CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 200),
    version integer NOT NULL DEFAULT 1,
    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (product_id, tenant_id) REFERENCES axentra_tenants (product_id, id) ON DELETE CASCADE,
    -- Deleting a project deletes its tasks; a task cannot point at another tenant's project.
    FOREIGN KEY (product_id, tenant_id, project_id)
        REFERENCES taskboard_projects (product_id, tenant_id, id) ON DELETE CASCADE,
    UNIQUE (product_id, tenant_id, idempotency_key)
);
CREATE INDEX taskboard_tasks_by_project ON taskboard_tasks (product_id, tenant_id, project_id, id);
CREATE INDEX taskboard_tasks_by_status ON taskboard_tasks (product_id, tenant_id, status);

-- Row-level security: rows are visible and writable only inside their product/tenant scope.
-- FORCE applies the policies to the table owner (the migration role) as well.
ALTER TABLE taskboard_projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE taskboard_projects FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON taskboard_projects
    USING (axentra_scope_allows(product_id, tenant_id))
    WITH CHECK (axentra_scope_allows(product_id, tenant_id));

ALTER TABLE taskboard_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE taskboard_tasks FORCE ROW LEVEL SECURITY;
CREATE POLICY scope ON taskboard_tasks
    USING (axentra_scope_allows(product_id, tenant_id))
    WITH CHECK (axentra_scope_allows(product_id, tenant_id));
