-- ADR-029 / issue #20: the off-chain, auditable usage-metering and
-- invoice ledger. Three properties the issue's own acceptance criteria
-- require, each enforced structurally by this schema, not just by
-- application discipline:
--
--   1. "PostgreSQL preserves adjustments and audit history" --
--      metering_evidence and invoice_lines are append-only: nothing in
--      internal/metering ever UPDATEs or DELETEs a row here. An
--      adjustment to an already-computed invoice line is a NEW
--      invoice_lines row whose supersedes_invoice_line_id points at the
--      one it corrects.
--   2. "missing/late/conflicting evidence never becomes silent billable
--      success" -- metering_evidence_rejections is where a duplicate,
--      out-of-order, clock-skewed, or overflowing submission is
--      recorded instead of silently dropped or silently billed. It is
--      never joined into anything billing-relevant.
--   3. "invoices are reproducible from source evidence" -- prices are
--      pinned via price_version (internal/metering's own versioned
--      constant table, not a mutable rate card row here), and
--      evidence_hash ties the computed amounts back to the exact
--      signed evidence that produced them, so total_amount can always
--      be recomputed and checked against what is stored.
--
-- metering_cursors is the atomic monotonicity gate: internal/metering
-- takes a row lock on (provider_id, workload_id) before checking
-- incoming.sequence > last_sequence, so two concurrent submissions for
-- the same workload cannot both observe "not yet seen" and double-
-- accept. metering_evidence's own UNIQUE(provider_id, workload_id,
-- sequence) is defense in depth behind that lock, not the primary
-- mechanism.
CREATE TABLE IF NOT EXISTS metering_cursors (
    provider_id text NOT NULL REFERENCES providers (provider_id),
    workload_id uuid NOT NULL REFERENCES workloads (workload_id),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, workload_id)
);

-- One row per accepted MeteringSummary (ADR-029 §6). All five priced/
-- reserved dimensions are bigint (Postgres has no native uint64; every
-- wire value internal/metering accepts is range-checked against
-- bigint's max before insertion here, the same "keep the bad row out of
-- the INSERT entirely" discipline workload_bandwidth_usage's RecordUsage
-- already established for its own uint64-on-the-wire/bigint-in-Postgres
-- boundary).
CREATE TABLE IF NOT EXISTS metering_evidence (
    evidence_id uuid PRIMARY KEY,
    provider_id text NOT NULL REFERENCES providers (provider_id),
    workload_id uuid NOT NULL REFERENCES workloads (workload_id),
    lease_id bigint NOT NULL CHECK (lease_id >= 0),
    sequence bigint NOT NULL CHECK (sequence > 0),
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL CHECK (period_end >= period_start),
    metering_schema_version integer NOT NULL CHECK (metering_schema_version > 0),
    cpu_core_seconds bigint NOT NULL CHECK (cpu_core_seconds >= 0),
    ram_mb_seconds bigint NOT NULL CHECK (ram_mb_seconds >= 0),
    storage_gb_seconds bigint NOT NULL CHECK (storage_gb_seconds >= 0),
    network_egress_mb bigint NOT NULL CHECK (network_egress_mb >= 0),
    network_ingress_mb bigint NOT NULL CHECK (network_ingress_mb >= 0),
    -- Reserved, priced at 0 and not billed in v1 (ADR-029 §1/§11) --
    -- carried through the schema now so a future GPU-billing PR is an
    -- additive price-table change, not a migration.
    gpu_seconds bigint NOT NULL CHECK (gpu_seconds >= 0),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    -- SHA-256 over the same canonical signed-byte encoding the
    -- signature itself covers (agent-api's METERING_DOMAIN construction,
    -- mirrored in internal/metering/signing.go) -- not a hash of this
    -- row or of any proto wire encoding. See internal/metering/signing.go's
    -- doc comment for why SHA-256 rather than blake2_256 (the on-chain
    -- convention) was chosen for this off-chain evidence_hash, and what
    -- #21 still needs to coordinate.
    evidence_hash bytea NOT NULL CHECK (octet_length(evidence_hash) = 32),
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_id, workload_id, sequence)
);

CREATE INDEX IF NOT EXISTS metering_evidence_workload_idx ON metering_evidence (workload_id, sequence);

-- Append-only audit trail of every submission internal/metering refused
-- to treat as billable: duplicate sequence, out-of-order/replayed
-- sequence (including an Agent restart that regressed its own
-- sequence), clock skew outside tolerance, a bound violation (period
-- too long, unknown schema version), an unverifiable signature, or a
-- charged-amount overflow. Deliberately has no foreign key to
-- metering_evidence (a rejected submission usually has no
-- corresponding accepted row at all) and workload_id/sequence are
-- nullable -- a malformed submission may not even carry a well-formed
-- workload_id to key on.
CREATE TABLE IF NOT EXISTS metering_evidence_rejections (
    rejection_id uuid PRIMARY KEY,
    provider_id text NOT NULL,
    workload_id uuid,
    sequence bigint,
    reason text NOT NULL,
    detail text,
    evidence_hash bytea,
    received_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS metering_evidence_rejections_provider_idx
    ON metering_evidence_rejections (provider_id, received_at);

-- One row per computed charge. consumer_id mirrors workloads.owner_id
-- (issue #12's user concept) at the moment the line was computed --
-- copied rather than joined live, so a later change to workloads.owner_id
-- (there is none today, but nothing prevents one) can never retroactively
-- change a historical invoice line's stated consumer.
CREATE TABLE IF NOT EXISTS invoice_lines (
    invoice_line_id uuid PRIMARY KEY,
    evidence_id uuid NOT NULL REFERENCES metering_evidence (evidence_id),
    provider_id text NOT NULL REFERENCES providers (provider_id),
    consumer_id uuid REFERENCES users (user_id),
    workload_id uuid NOT NULL REFERENCES workloads (workload_id),
    lease_id bigint NOT NULL CHECK (lease_id >= 0),
    price_version integer NOT NULL CHECK (price_version > 0),
    cpu_amount bigint NOT NULL CHECK (cpu_amount >= 0),
    ram_amount bigint NOT NULL CHECK (ram_amount >= 0),
    storage_amount bigint NOT NULL CHECK (storage_amount >= 0),
    network_amount bigint NOT NULL CHECK (network_amount >= 0),
    total_amount bigint NOT NULL CHECK (total_amount >= 0),
    evidence_hash bytea NOT NULL CHECK (octet_length(evidence_hash) = 32),
    -- NULL: this is the original line computed directly from
    -- evidence_id's evidence. Non-NULL: this row is a correction, and
    -- the row it points at (which is never itself modified or deleted)
    -- is superseded for billing-total purposes but stays permanently
    -- readable for audit.
    supersedes_invoice_line_id uuid REFERENCES invoice_lines (invoice_line_id),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- At most one "original" (non-adjustment) invoice line per evidence row
-- -- RecordUsage's idempotent-retry path relies on being able to look
-- this one row up by evidence_id alone. Adjustments (supersedes_invoice_
-- line_id IS NOT NULL) are unrestricted in number and excluded from this
-- index entirely (a partial index, not a plain UNIQUE column).
CREATE UNIQUE INDEX IF NOT EXISTS invoice_lines_original_per_evidence_idx
    ON invoice_lines (evidence_id) WHERE supersedes_invoice_line_id IS NULL;

CREATE INDEX IF NOT EXISTS invoice_lines_provider_idx ON invoice_lines (provider_id, created_at);
CREATE INDEX IF NOT EXISTS invoice_lines_consumer_idx ON invoice_lines (consumer_id, created_at);

-- "A flagged/conflicting evidence record must be inspectable, not
-- silently resolved either way" (issue #20's own acceptance criterion).
-- Raising a dispute here is the off-chain, human/operator-inspectable
-- counterpart to ADR-029 §4.4's on-chain dispute_escrow -- resolution
-- (status transition away from 'open') is deliberately not automated by
-- anything in this PR; see internal/metering's doc comments for what is
-- and is not implemented.
CREATE TABLE IF NOT EXISTS metering_disputes (
    dispute_id uuid PRIMARY KEY,
    invoice_line_id uuid NOT NULL REFERENCES invoice_lines (invoice_line_id),
    raised_by text NOT NULL CHECK (raised_by IN ('payer', 'provider', 'operator')),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved_pay_provider', 'resolved_refund_payer')),
    raised_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    resolution_note text
);

CREATE INDEX IF NOT EXISTS metering_disputes_invoice_line_idx ON metering_disputes (invoice_line_id);
CREATE INDEX IF NOT EXISTS metering_disputes_open_idx ON metering_disputes (status) WHERE status = 'open';
