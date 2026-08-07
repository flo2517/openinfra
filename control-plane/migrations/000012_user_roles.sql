-- ADR-016 slice 1: dashboard RBAC's schema. A single role column, not a
-- many-to-many table -- every real actor today (tenant, operator) has
-- exactly one job; see ADR-016 §1 for why a join table is deliberately
-- deferred rather than built speculatively.
--
-- DEFAULT 'tenant' means every existing user (created before this
-- migration, via controlplane-admin create-user or wallet auto-
-- provisioning) becomes a tenant, the least-privileged role, rather than
-- an operator -- a fail-closed default: nobody is silently upgraded to
-- operator by this migration, an explicit `controlplane-admin grant-role`
-- is required for that.
ALTER TABLE users ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'tenant'
    CHECK (role IN ('tenant', 'operator'));
