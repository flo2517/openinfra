-- ADR-037 / issue #35: durable record of every signed, content-addressed
-- dashboard frontend release this project has published. This table is
-- the Postgres-authoritative source `GET /.well-known/openinfra-frontend`
-- (internal/dashboard's wellknown.go) serves from, and what the
-- CORS/origin-allowlist middleware (internal/dashboard's cors.go) reads
-- its currently-trusted `allowed_login_origins` from (ADR-037 §4/§7): the
-- "latest, non-revoked" row is the single source of truth for both.
--
-- Rows are never deleted or mutated in place (ADR-037 §9 rollback and §7
-- takedown are both *new* rows, never an UPDATE of an existing release's
-- content) -- only `revoked_at`/`revoked_reason` are ever written after
-- insert, exactly mirroring how a certificate revocation (ADR-027) marks
-- a cert revoked rather than deleting its row. `manifest_json` holds the
-- exact signed manifest bytes the release pipeline produced (ADR-037 §2
-- step 3/4) verbatim, so `.well-known` can return byte-identical content
-- to what was actually signed -- the indexed columns alongside it exist
-- for querying, not as a second, potentially-drifting copy of the truth.
CREATE TABLE IF NOT EXISTS frontend_releases (
    release_id text PRIMARY KEY,
    cid text NOT NULL CHECK (length(cid) > 0),
    manifest_sha256 text NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    -- Hex-encoded Ed25519 signature (ADR-037 §2 step 4): 64 bytes = 128
    -- hex characters. This CHECK only enforces the hex/length shape, not
    -- cryptographic validity -- Publish additionally verifies against
    -- PostgresRepository.trustedPublicKey when one is configured
    -- (internal/frontendrelease/postgres.go's WithTrustedPublicKey), and
    -- the actual, load-bearing verification happens at read time: every
    -- row this table holds is re-verified with frontendrelease.Verify
    -- against cmd/controlplane/main.go's FRONTEND_RELEASE_PUBLIC_KEY (the
    -- fixed, deploy-configured trust anchor read once at startup) before
    -- GET /.well-known/openinfra-frontend serves it or the CORS allowlist
    -- (internal/dashboard's cors.go) trusts its allowed_login_origins --
    -- an unset FRONTEND_RELEASE_PUBLIC_KEY fails closed (nothing is ever
    -- trusted) rather than skipping verification. ADR-037's own "custody
    -- and rotation not decided here" open question still applies to where
    -- the corresponding private key lives.
    signature text NOT NULL CHECK (signature ~ '^[0-9a-f]{128}$'),
    api_origin text NOT NULL,
    -- ADR-037 §4's phishing-resistance control: the exact origin list this
    -- release's CORS allowlist trusts for credentialed requests. Stored
    -- per-release (not globally) so revoking a release (see revoked_at
    -- below) genuinely removes its trust grant the moment it stops being
    -- "latest, non-revoked" -- not a separate, independently-mutable
    -- setting that could drift from what was actually signed.
    allowed_login_origins jsonb NOT NULL,
    previous_cid text,
    released_at timestamptz NOT NULL,
    -- The full signed manifest object (schema_version, release_id, cid,
    -- files[], manifest_sha256, api_origin, allowed_login_origins,
    -- previous_cid, released_at, signature) exactly as produced by the
    -- release pipeline and served verbatim by .well-known -- see comment
    -- above.
    manifest_json jsonb NOT NULL,
    -- ADR-037 §7 emergency takedown: set together, never independently.
    -- A revoked release is simply excluded from "latest, non-revoked" --
    -- it is never deleted (the row itself is the audit trail of what was
    -- revoked, when, and why).
    revoked_at timestamptz,
    revoked_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);

-- The query every request to .well-known and every credentialed request's
-- CORS check runs: "the newest release that is not revoked." Partial
-- index (WHERE revoked_at IS NULL) keeps it small regardless of how many
-- releases accumulate in `created_at` order over the project's life, even
-- though ADR-037 §8 only plans to keep the last 10 *pinned* in kubo --
-- this table's own retention is a separate, cheap, append-only history,
-- not bounded by that pinning window.
CREATE INDEX IF NOT EXISTS frontend_releases_active_idx
    ON frontend_releases (released_at DESC) WHERE revoked_at IS NULL;
