-- ADR-034 / issue #171 (Cinder half of issue #26): durable metadata for
-- Cinder-compatible block volumes -- a project-scoped, host-local Docker
-- named volume whose bytes live entirely on the one provider host it is
-- ever attached to (ADR-034 §1). This table is the Postgres-authoritative
-- half of ADR-034 §3's durable-state split; the Agent's own local `sled`
-- state only ever records what it actually mounted, and is reconciled
-- against this table's `state`/`provider_id`/`attached_workload_id`
-- columns, never treated as a second authority.
--
-- Lifecycle (ADR-034 §2): available -> in-use (attach) -> available
-- (detach) -> deleting -> row soft-deleted (deleted_at set), matching
-- glance_images' own "no hard DELETE FROM" precedent extended here with
-- an explicit transitional 'deleting' state, since -- unlike an image
-- row -- a volume delete triggers real, possibly-failing, Agent-side work
-- (ADR-034 §6's overwrite-before-remove) between "caller asked to delete"
-- and "actually gone".
CREATE TABLE IF NOT EXISTS cinder_volumes (
    volume_id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(project_id),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    -- Real Cinder's own unit. A generous but finite upper bound, the same
    -- defense-in-depth ceiling project_quotas/glance_images already
    -- apply to their own numeric columns -- the actual enforcement is
    -- project_quotas.max_storage_gb (ADR-034 §4), checked at create time
    -- by internal/projects.CheckQuota, not this CHECK constraint.
    size_gb integer NOT NULL CHECK (size_gb > 0 AND size_gb <= 1000000),
    -- available: exists, unattached, may be attached or deleted.
    -- in-use: attached to exactly one workload on provider_id -- the
    --   structural double-attachment guard (ADR-034 §2) is the UPDATE …
    --   WHERE state='available' transition into this state, checked in
    --   the same statement that performs it (internal/openstackapi/cinder
    --   .Repository.AttachVolume), never a separate read-then-write.
    -- deleting: a DELETE has been accepted and secure deletion (ADR-034
    --   §6) is in flight on provider_id; only reachable from available.
    -- error: reserved for a future slice's failure surfacing; not
    --   produced by this PR's own code paths, but kept in the CHECK
    --   constraint now so a later PR adding real error-state handling is
    --   an additive change, not another migration.
    state text NOT NULL DEFAULT 'available' CHECK (state IN ('available', 'in-use', 'deleting', 'error')),
    -- NULL until first attach (ADR-034 §2: "nothing is created on any
    -- provider host until the volume is first attached"); permanently
    -- set on first attach and never changed again after that (ADR-034
    -- §1: no cross-provider portability) -- enforced in Go
    -- (AttachVolume rejects a second provider), not by a CHECK
    -- constraint, since "may only be set once, to any one of many valid
    -- values" is not expressible as a column-local CHECK.
    provider_id text REFERENCES providers(provider_id),
    -- The one workload currently holding this volume attached, NULL
    -- whenever state != 'in-use'. Enforced together (see the CHECK
    -- below) so an 'in-use' row can never be caught with no recorded
    -- attachment, and an 'available'/'deleting' row can never be caught
    -- still pointing at a stale workload.
    attached_workload_id uuid REFERENCES workloads(workload_id),
    -- The in-container mount path this attachment was requested at (real
    -- Cinder's own "mountpoint" os-attach field, kept under this name
    -- since that is what a wire-compatible client actually sends) --
    -- NULL whenever attached_workload_id is NULL, populated at attach,
    -- cleared at detach. internal/orchestrator's deploy dispatch reads
    -- this (joined with provider_id) to populate DeployRequest.volumes
    -- (agent.proto's VolumeAttachment, ADR-034 §7) for any workload whose
    -- deploy has not yet been dispatched when the attach happens -- see
    -- that package's own doc comment for the named limitation this
    -- ordering leaves (attaching to an already-*running* workload does
    -- not trigger a remount).
    mount_path text CHECK (mount_path IS NULL OR length(mount_path) BETWEEN 1 AND 255),
    read_only boolean NOT NULL DEFAULT false,
    -- ADR-034 §6: always false in this PR -- encryption at rest is a
    -- named, explicit MVP non-goal, not silently unset. Present now
    -- (rather than added in a later migration) so a future encryption
    -- slice is an additive UPDATE, not another schema change, matching
    -- ADR-034's own Consequences section listing this column today.
    encrypted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- Soft-delete marker, glance_images-style, set only after ADR-034
    -- §6's secure-deletion step has completed on the owning provider.
    deleted_at timestamptz,
    CHECK ((state = 'in-use') = (attached_workload_id IS NOT NULL)),
    CHECK ((attached_workload_id IS NOT NULL) = (mount_path IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS cinder_volumes_project_idx ON cinder_volumes (project_id) WHERE deleted_at IS NULL;

-- Indexed for "every volume this provider currently holds in-use", the
-- exact set a heartbeat-silent provider's reconciliation pass would need
-- to read, mirroring how internal/orchestrator's own workload
-- reconciliation queries are indexed by provider+state.
--
-- KNOWN GAP (found in the issue #26 security review that also produced
-- the CreateVolume atomic-quota-check and DeployRequest.volumes-wiring
-- fixes landed alongside this comment change): no such reconciliation
-- pass actually exists yet, despite this comment previously claiming one
-- did. A volume permanently bound (ADR-034 §1: first-attach binding is
-- for the volume's whole life) to a provider that goes permanently
-- unreachable can today never be reattached or securely deleted (ADR-034
-- §6 delete requires reaching the bound provider) -- it sits 'in-use'
-- forever, consuming the project's storage_gb quota with no admin path
-- to release it. This index is real and ready for that reconciliation
-- pass whenever it's built; until then, treat the gap above as
-- documented, not silently mitigated by this index existing.
CREATE INDEX IF NOT EXISTS cinder_volumes_provider_state_idx ON cinder_volumes (provider_id, state) WHERE deleted_at IS NULL;

-- At most one live (non-deleted) row may claim a given attached_workload_id
-- at a time -- a second, independent backstop behind the Go-level
-- transactional attach check (defense in depth, the same pattern
-- project_quotas/glance_images' CHECK constraints already establish
-- alongside their own Go-level validation).
CREATE UNIQUE INDEX IF NOT EXISTS cinder_volumes_attached_workload_idx
    ON cinder_volumes (attached_workload_id) WHERE attached_workload_id IS NOT NULL AND deleted_at IS NULL;
