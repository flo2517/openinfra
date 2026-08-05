ALTER TABLE workloads DROP CONSTRAINT IF EXISTS workloads_state_check;
ALTER TABLE workloads ADD CONSTRAINT workloads_state_check CHECK (state IN (
    'REQUESTED','SCHEDULING','LEASE_PENDING','LEASED','DEPLOYING','RUNNING',
    'STOPPING','STOPPED','COMPLETED','FAILED'
));
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS stop_request_id uuid UNIQUE;
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS stop_requested_at timestamptz;
