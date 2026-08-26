-- ADR-031 §3 / issue #23: schema for the Keystone-compatible identity
-- bridge (internal/openstackapi). Projects and project_memberships give
-- Keystone's domain -> project -> user model (single implicit "default"
-- domain for this slice) a real representation for the first time --
-- users.role (migration 000012/000013) stays exactly as ADR-016 defined
-- it (a system-wide dashboard-visibility tier) and is not touched here;
-- project_memberships.role answers a different question ("what may this
-- user do inside this specific project") with its own, deliberately
-- smaller, two-level set.
--
-- project_quotas is a second, independent per-project resource ceiling,
-- checked alongside (never instead of) internal/workloadapi's existing
-- per-provider ProviderCapacity ceiling. A project with no project_quotas
-- row is unbounded on the quota dimension specifically -- ADR-031 §3's
-- deliberate fail-open default so pre-quota projects aren't silently
-- locked out -- but the CHECK constraints below make sure a *configured*
-- row can never itself be unbounded or negative: every dimension must be
-- a real, positive, sane-upper-bounded number.
CREATE TABLE IF NOT EXISTS projects (
    project_id uuid PRIMARY KEY,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Keystone project names are unique within a domain; this system has
-- exactly one (implicit "default") domain for this slice, so unique
-- globally is the correct scope today -- revisit only alongside real
-- multi-domain support (ADR-031 §3/§8, explicitly deferred).
CREATE UNIQUE INDEX IF NOT EXISTS projects_name_idx ON projects (name);

CREATE TABLE IF NOT EXISTS project_memberships (
    project_id uuid NOT NULL REFERENCES projects(project_id),
    user_id uuid NOT NULL REFERENCES users(user_id),
    -- project_member / project_admin: the two levels ADR-031 §3
    -- deliberately settles for the first slice (Keystone's own
    -- common-case split), not Keystone's full custom-policy engine.
    role text NOT NULL CHECK (role IN ('project_member', 'project_admin')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id)
);

CREATE INDEX IF NOT EXISTS project_memberships_user_idx ON project_memberships (user_id);

CREATE TABLE IF NOT EXISTS project_quotas (
    project_id uuid PRIMARY KEY REFERENCES projects(project_id),
    max_cpu_millicores integer NOT NULL CHECK (max_cpu_millicores > 0 AND max_cpu_millicores <= 1000000000),
    max_ram_mb bigint NOT NULL CHECK (max_ram_mb > 0 AND max_ram_mb <= 1000000000000),
    max_storage_gb bigint NOT NULL CHECK (max_storage_gb > 0 AND max_storage_gb <= 1000000000000),
    max_workloads integer NOT NULL CHECK (max_workloads > 0 AND max_workloads <= 1000000),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Nullable, the same "pre-existing rows have no owner" pattern 000009
-- used for workloads.owner_id: a workload created before this migration
-- (or through a path other than the OpenStack surface) has no project.
-- Every workload the OpenStack surface creates populates it.
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS project_id uuid REFERENCES projects(project_id);
CREATE INDEX IF NOT EXISTS workloads_project_idx ON workloads (project_id);

-- ADR-031 §3's token bridge: a Keystone-shaped token is, internally, one
-- more api_keys row -- this column records which project (if any) it is
-- scoped to. NULL means unscoped, which describes every key that exists
-- before this migration and every key minted outside the OpenStack
-- surface (e.g. controlplane-admin issue-key, wallet login).
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS project_id uuid REFERENCES projects(project_id);
CREATE INDEX IF NOT EXISTS api_keys_project_idx ON api_keys (project_id) WHERE project_id IS NOT NULL;
