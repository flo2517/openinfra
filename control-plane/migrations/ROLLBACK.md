# Manual rollback SQL

`migrations.Apply` (`migrations.go`) is forward-only: it applies every
`NNNNNN_*.sql` file in this directory once, tracked in a `schema_migrations`
ledger, and there is no `migrate down` command. That is an intentional MVP
simplification, not an oversight — but issue #17 asks for rollback
*documentation* to exist and to actually be checked, so this file is the
maintained, hand-verified reverse of every migration in this directory, and
`tests/e2e/suites/30-migrations-rollback.sh` mechanically executes it against
a real scratch database (apply all forward, apply this file's SQL in reverse
migration order, confirm the schema returns to empty, re-apply forward,
confirm the ledger matches again) so this document cannot silently drift from
the schema it describes.

**Rules for keeping this file honest:**
- Every migration added to this directory gets a section here in the same
  commit, in the same numeric position (rollback runs in *reverse* numeric
  order — highest-numbered migration rolled back first, since later
  migrations may depend on earlier ones' tables/columns).
- A rollback statement that can fail on non-empty/incompatible data (e.g.
  restoring a stricter CHECK constraint) says so explicitly, with the
  precondition that makes it safe.
- Where forward data was *transformed* (not just added), rollback cannot
  losslessly undo it; that is called out rather than papered over with SQL
  that merely doesn't error.

Run manually (against a real database, never against `$POSTGRES_DB` in the
Compose dev stack unless you mean it) with `psql -f`, applying each block in
the order below, top to bottom.

## 000018_workload_vm_image_digest.sql
```sql
ALTER TABLE workloads DROP COLUMN IF EXISTS vm_image_sha256;
```

## 000017_projects_and_quotas.sql
Precondition: no `api_keys` or `workloads` row currently has `project_id` set
to a project this rollback is about to delete transitively via `DROP TABLE
projects` failing on the FK -- in practice this means rolling back 000017
only makes sense against an empty/fresh scratch database (suite 30's case),
the same caveat 000009's section below already states for `users`/
`workloads.owner_id`.
```sql
DROP INDEX IF EXISTS api_keys_project_idx;
ALTER TABLE api_keys DROP COLUMN IF EXISTS project_id;
DROP INDEX IF EXISTS workloads_project_idx;
ALTER TABLE workloads DROP COLUMN IF EXISTS project_id;
DROP TABLE IF EXISTS project_quotas;
DROP TABLE IF EXISTS project_memberships;
DROP INDEX IF EXISTS projects_name_idx;
DROP TABLE IF EXISTS projects;
```

## 000016_metering_evidence_and_invoices.sql
Drop order matters here (no `CASCADE`): `metering_disputes` references
`invoice_lines`, which references `metering_evidence`; the other two new
tables (`metering_evidence_rejections`, `metering_cursors`) have no FK to
any other table this migration added.
```sql
DROP TABLE IF EXISTS metering_disputes;
DROP TABLE IF EXISTS invoice_lines;
DROP TABLE IF EXISTS metering_evidence_rejections;
DROP TABLE IF EXISTS metering_evidence;
DROP TABLE IF EXISTS metering_cursors;
```

## 000015_workload_bandwidth_usage.sql
```sql
DROP TABLE IF EXISTS workload_bandwidth_usage;
```

## 000014_audit_events.sql
```sql
DROP TABLE IF EXISTS audit_events;
```

## 000013_operator_role_levels.sql
Not losslessly reversible: the forward migration's
`UPDATE users SET role = 'operator_admin' WHERE role = 'operator'` collapses
information (every legacy `'operator'` row becomes indistinguishable from a
row that was granted `'operator_admin'` directly after this migration ran).
The SQL below restores the *shape* (the two-level constraint reverts to the
one-level one) and coerces every `operator_admin`/`operator_readonly` row
back to `'operator'`, which is safe to run but is a real, irreversible loss
of the read-only/admin distinction if any had been granted. Do not roll this
back once ADR-016's two operator levels are in real use; the two-line UPDATE
below is the only lossy step in this entire document.
```sql
UPDATE users SET role = 'operator' WHERE role IN ('operator_admin', 'operator_readonly');
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('tenant', 'operator'));
```

## 000012_user_roles.sql
```sql
ALTER TABLE users DROP COLUMN IF EXISTS role;
```

## 000011_wallet_login.sql
```sql
DROP TABLE IF EXISTS wallet_accounts;
DROP TABLE IF EXISTS user_login_challenges;
```

## 000010_workload_bandwidth_reservation.sql
Precondition: no other session holds the covering index while this runs
(same caveat as any `DROP INDEX` on a live table; Compose's control-plane
should be stopped or this run against a scratch database, which is what
suite 30 does).
```sql
DROP INDEX IF EXISTS workloads_provider_reservation_idx;
CREATE INDEX IF NOT EXISTS workloads_provider_reservation_idx
    ON workloads (provider_id)
    INCLUDE (reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb)
    WHERE state IN ('LEASE_PENDING', 'LEASED', 'DEPLOYING', 'RUNNING');
ALTER TABLE workloads DROP COLUMN IF EXISTS reserved_egress_mbps;
ALTER TABLE workloads DROP COLUMN IF EXISTS reserved_ingress_mbps;
```

## 000009_users_and_api_keys.sql
Precondition: no `workloads` row currently has `owner_id` set to a user this
rollback is about to delete transitively via `DROP TABLE users` failing on
the FK -- in practice this means rolling back 000009 only makes sense with
an empty `workloads` table (a fresh scratch database, as suite 30 uses), not
against a database with real tenant history.
```sql
ALTER TABLE workloads DROP COLUMN IF EXISTS owner_id;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS users;
```

## 000008_workload_capacity_reservation.sql
```sql
DROP INDEX IF EXISTS workloads_provider_reservation_idx;
ALTER TABLE workloads DROP COLUMN IF EXISTS reserved_storage_gb;
ALTER TABLE workloads DROP COLUMN IF EXISTS reserved_ram_mb;
ALTER TABLE workloads DROP COLUMN IF EXISTS reserved_cpu_millicores;
```

## 000007_workload_worker_claims.sql
```sql
DROP INDEX IF EXISTS workloads_worker_claim_idx;
ALTER TABLE workloads DROP COLUMN IF EXISTS worker_id;
```

## 000006_workload_stop.sql
Precondition: no `workloads` row is currently in `'STOPPING'` or
`'STOPPED'` -- restoring the narrower CHECK constraint fails otherwise (by
design: the constraint is what makes an incompatible rollback fail loudly
instead of leaving inconsistent data behind).
```sql
ALTER TABLE workloads DROP COLUMN IF EXISTS stop_requested_at;
ALTER TABLE workloads DROP COLUMN IF EXISTS stop_request_id;
ALTER TABLE workloads DROP CONSTRAINT IF EXISTS workloads_state_check;
ALTER TABLE workloads ADD CONSTRAINT workloads_state_check CHECK (state IN (
    'REQUESTED', 'SCHEDULING', 'LEASE_PENDING', 'LEASED',
    'DEPLOYING', 'RUNNING', 'COMPLETED', 'FAILED'
));
```

## 000005_workload_lease_sequence.sql
```sql
DROP SEQUENCE IF EXISTS workload_lease_id_seq;
```

## 000004_workloads.sql
Depends on every migration above this one already being rolled back first
(000005's sequence and every `ALTER TABLE workloads ADD COLUMN` from
000006-000010 must already be gone, or this DROP TABLE simply takes them
with it -- which is also fine, `DROP TABLE` is not column-order-sensitive,
but the columns/indexes those migrations documented rolling back will
already have been removed by this point if this file is applied top to
bottom as intended).
```sql
DROP TABLE IF EXISTS workloads;
```

## 000003_provider_agent_endpoint.sql
```sql
ALTER TABLE providers DROP COLUMN IF EXISTS agent_endpoint;
ALTER TABLE provider_join_challenges DROP COLUMN IF EXISTS agent_endpoint;
```

## 000002_provider_chain_registration.sql
```sql
DROP TABLE IF EXISTS provider_chain_registrations;
ALTER TABLE providers DROP COLUMN IF EXISTS activated_at;
ALTER TABLE providers DROP COLUMN IF EXISTS updated_at;
```

## 000001_provider_join.sql
```sql
DROP TABLE IF EXISTS provider_join_completions;
DROP TABLE IF EXISTS provider_join_challenges;
DROP TABLE IF EXISTS providers;
```

## schema_migrations
Not a numbered migration -- `migrations.Apply` creates this ledger table
itself, outside the embedded `.sql` files. A full rollback (all of the above,
in order) leaves it present but empty; drop it last only if you want no
trace at all that migrations ever ran here:
```sql
DROP TABLE IF EXISTS schema_migrations;
```
