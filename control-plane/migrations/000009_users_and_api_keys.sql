-- Issue #12: authenticated identities and PostgreSQL-owned authorization
-- data for the user-facing workload API. API keys are never stored raw --
-- only a SHA-256 hash, so a database dump alone can never be replayed as a
-- credential.
CREATE TABLE IF NOT EXISTS users (
    user_id uuid PRIMARY KEY,
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(user_id),
    key_hash bytea NOT NULL UNIQUE CHECK (octet_length(key_hash) = 32),
    -- First 8 characters of the raw key, kept only for human-readable
    -- identification in logs/admin listings -- never enough entropy to
    -- reconstruct the key, so this is safe to log where the full key isn't.
    prefix text NOT NULL CHECK (length(prefix) = 8),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    revoked_at timestamptz,
    last_used_at timestamptz
);

CREATE INDEX IF NOT EXISTS api_keys_user_idx ON api_keys (user_id);

-- Nullable: pre-existing workloads created before this migration have no
-- owner and become permanently inaccessible through the authenticated user
-- API (an intentional fail-closed default, not a bug -- see
-- internal/workloadapi ownership checks). New submissions always populate it.
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS owner_id uuid REFERENCES users(user_id);
CREATE INDEX IF NOT EXISTS workloads_owner_idx ON workloads (owner_id);
