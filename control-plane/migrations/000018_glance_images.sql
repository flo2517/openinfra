-- ADR-031 §2 / issue #26 (Glance subset only -- Cinder's block-volume
-- half is issue #171, gated behind ADR-034's acceptance and deliberately
-- not implemented here): a project-scoped image *registry* -- durable
-- metadata about an image reference (a name, a source location, and the
-- digest a caller already pins it to) a client already trusts, not a
-- store of image bytes. The actual bytes continue to be fetched by the
-- provider-agent's own existing, separately-audited paths (Docker pull
-- for container images, ADR-033 §4's fetch_and_verify_image for VM
-- qcow2 images) -- this table only ever holds the catalog entry those
-- paths are looked up from.
--
-- Immutability: internal/openstackapi/glance exposes no update/PATCH
-- route at all -- an image row's digest_sha256 (or any other column) can
-- never be mutated once created, enforced structurally (no code path
-- exists to do it) rather than by a trigger. A caller who needs a new
-- digest creates a new image row and deletes the old one -- "superseded",
-- never mutated in place.
CREATE TABLE IF NOT EXISTS glance_images (
    image_id uuid PRIMARY KEY,
    project_id uuid NOT NULL REFERENCES projects(project_id),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    -- The location a provider-agent fetches the actual bytes from at
    -- deploy time -- an https:// URL (ADR-033 §4's VM image convention)
    -- or an OCI registry reference (the same shape
    -- internal/workloadapi.digestImage already validates for container
    -- images). Deliberately not format-constrained here beyond a length
    -- bound: this table never fetches or dereferences it itself, so
    -- there is no SSRF surface to defend against at this layer -- that
    -- defense already lives where the bytes are actually fetched.
    source_ref text NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 2000),
    -- Exactly 64 lowercase hex characters -- the same
    -- vm_image_sha256/validate_sha256_hex discipline ADR-033's
    -- provider-agent/crates/agent-executor/src/vm/image.rs enforces for
    -- VM images, replicated here as a second, independent backstop
    -- behind the Go handler's own identical regex check (defense in
    -- depth, the same pattern project_quotas/projects already use for
    -- their own CHECK constraints).
    digest_sha256 text NOT NULL CHECK (digest_sha256 ~ '^[a-f0-9]{64}$'),
    size_bytes bigint CHECK (size_bytes IS NULL OR size_bytes > 0),
    -- private: only the owning project (project_id above) may list/get
    -- it. public: any authenticated, project-scoped caller may list/get
    -- it (but never delete it -- only the owning project can). The
    -- simple two-state model issue #26 asks for, not Keystone/Glance's
    -- full community/shared-with-specific-projects visibility set.
    visibility text NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'public')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS glance_images_project_idx ON glance_images (project_id);

-- Speeds the "OR visibility = 'public'" branch every list/get query
-- carries -- a project scanning its own images is already covered by the
-- index above, but resolving public images shared from every other
-- project would otherwise be a full table scan.
CREATE INDEX IF NOT EXISTS glance_images_public_idx ON glance_images (visibility) WHERE visibility = 'public';
