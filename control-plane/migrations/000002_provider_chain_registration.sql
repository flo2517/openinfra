ALTER TABLE providers
    ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS activated_at timestamptz;

CREATE TABLE IF NOT EXISTS provider_chain_registrations (
    provider_id text PRIMARY KEY REFERENCES providers(provider_id),
    state text NOT NULL CHECK (state IN ('READY', 'SUBMITTED', 'FINALIZED', 'RETRY', 'FAILED')),
    extrinsic_hash bytea,
    finalized_block_hash bytea,
    finalized_block_number bigint CHECK (finalized_block_number >= 0),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    finalized_at timestamptz
);

CREATE INDEX IF NOT EXISTS provider_chain_registrations_retry_idx
    ON provider_chain_registrations (state, next_attempt_at)
    WHERE state IN ('READY', 'RETRY', 'SUBMITTED');
