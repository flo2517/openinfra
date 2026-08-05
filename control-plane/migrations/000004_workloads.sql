CREATE TABLE IF NOT EXISTS workloads (
    workload_id uuid PRIMARY KEY,
    request_id uuid NOT NULL UNIQUE,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    definition bytea NOT NULL,
    image text NOT NULL,
    state text NOT NULL CHECK (state IN (
        'REQUESTED', 'SCHEDULING', 'LEASE_PENDING', 'LEASED',
        'DEPLOYING', 'RUNNING', 'COMPLETED', 'FAILED'
    )),
    provider_id text REFERENCES providers(provider_id),
    lease_id bigint UNIQUE CHECK (lease_id >= 0),
    resource_hash bytea CHECK (resource_hash IS NULL OR octet_length(resource_hash) = 32),
    container_id text,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at timestamptz,
    worker_lease_until timestamptz,
    error_code text,
    last_error text,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (state NOT IN ('LEASE_PENDING', 'LEASED', 'DEPLOYING', 'RUNNING', 'COMPLETED') OR provider_id IS NOT NULL),
    CHECK (state NOT IN ('LEASED', 'DEPLOYING', 'RUNNING', 'COMPLETED') OR lease_id IS NOT NULL),
    CHECK (state NOT IN ('RUNNING', 'COMPLETED') OR container_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS workloads_dispatch_idx
    ON workloads (state, next_attempt_at, created_at)
    WHERE state NOT IN ('COMPLETED', 'FAILED');
