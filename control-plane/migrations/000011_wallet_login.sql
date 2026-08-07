-- ADR-014: wallet-based dashboard login. A user proves control of a key
-- by signing a server-issued nonce (the same challenge/signature pattern
-- provider_join_challenges already uses for providers), rather than
-- authenticating with a password or a pre-shared token.

-- Mirrors provider_join_challenges' exact shape and lifecycle: short-lived,
-- single-use (consumed_at set atomically on successful login), never
-- reused across requests.
CREATE TABLE IF NOT EXISTS user_login_challenges (
    challenge_id uuid PRIMARY KEY,
    nonce bytea NOT NULL CHECK (octet_length(nonce) = 32),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE INDEX IF NOT EXISTS user_login_challenges_expiry_idx
    ON user_login_challenges (expires_at)
    WHERE consumed_at IS NULL;

-- Maps a wallet account to the users row it authenticates as. One account
-- maps to exactly one user; a user may have more than one linked account
-- (no UI for adding a second one yet, but the schema doesn't need to
-- change to support it later).
CREATE TABLE IF NOT EXISTS wallet_accounts (
    account_id bytea PRIMARY KEY CHECK (octet_length(account_id) = 32),
    -- 0 = Ed25519, 1 = Sr25519 (Sr25519 verification is a later
    -- implementation slice; the column exists now so it never needs a
    -- later migration).
    scheme smallint NOT NULL CHECK (scheme IN (0, 1)),
    user_id uuid NOT NULL REFERENCES users(user_id),
    linked_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS wallet_accounts_user_idx ON wallet_accounts (user_id);
