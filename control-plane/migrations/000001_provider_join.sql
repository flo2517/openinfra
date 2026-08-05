CREATE TABLE IF NOT EXISTS providers (
    provider_id text PRIMARY KEY,
    public_key bytea NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    protocol_version text NOT NULL,
    agent_version text NOT NULL,
    capabilities bytea NOT NULL,
    status smallint NOT NULL,
    registered_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_join_challenges (
    challenge_id uuid PRIMARY KEY,
    begin_request_id uuid NOT NULL UNIQUE,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    protocol_version text NOT NULL,
    agent_version text NOT NULL,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 32),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    provider_id text REFERENCES providers(provider_id)
);

CREATE TABLE IF NOT EXISTS provider_join_completions (
    request_id uuid PRIMARY KEY,
    challenge_id uuid NOT NULL REFERENCES provider_join_challenges(challenge_id),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    provider_id text NOT NULL REFERENCES providers(provider_id),
    registered_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS provider_join_challenges_expiry_idx
    ON provider_join_challenges (expires_at)
    WHERE consumed_at IS NULL;
