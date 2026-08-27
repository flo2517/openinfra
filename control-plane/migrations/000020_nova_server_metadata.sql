-- ADR-031 §4 / issue #24: persistent state for the Nova-compatible
-- server-lifecycle API (internal/openstackapi/nova). A Nova "server" is
-- an existing `workloads` row underneath -- no parallel execution model,
-- per ADR-031 §4's compute-mapping table -- so this table carries only
-- the Nova-specific fields `workloads` has no column for:
--
--   - name: Nova's tenant-chosen display name; `workloads` has none.
--   - flavor_id: which flavor the caller requested. Not re-derivable from
--     the stored ResourceRequirements alone -- two differently-priced/
--     named flavors can resolve to the same CPU/RAM/storage triple, so
--     GET /servers/{id} echoing back a flavor would otherwise have to
--     guess.
--   - metadata: Nova's free-form os-server-metadata key/value extension,
--     which nothing in this schema has ever needed before.
--
-- One row per Nova-created workload, 1:1 keyed by workload_id. Not
-- deleted when a server is "deleted" (DELETE /servers/{id} only calls
-- RequestStopByProject, exactly like internal/dashboard's
-- stopMyWorkload) -- workloads rows are never hard-deleted anywhere in
-- this schema, and this table follows the same convention so a stopped
-- server's name/flavor/metadata remain inspectable in Postgres for
-- operator debugging, the same way the workload's own row does.
CREATE TABLE IF NOT EXISTS nova_server_metadata (
    workload_id uuid PRIMARY KEY REFERENCES workloads(workload_id),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    flavor_id text NOT NULL CHECK (length(flavor_id) BETWEEN 1 AND 100),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now()
);
