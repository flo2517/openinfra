ALTER TABLE workloads ADD COLUMN IF NOT EXISTS worker_id text;

CREATE INDEX IF NOT EXISTS workloads_worker_claim_idx
    ON workloads (next_attempt_at, worker_lease_until, created_at)
    WHERE state IN (
        'REQUESTED','SCHEDULING','LEASE_PENDING','LEASED','DEPLOYING','STOPPING'
    );

COMMENT ON COLUMN workloads.worker_id IS
    'Opaque Control Plane worker instance holding the renewable, expiring claim';
COMMENT ON COLUMN workloads.worker_lease_until IS
    'Claim expiry; another instance may recover the workload after this instant';
