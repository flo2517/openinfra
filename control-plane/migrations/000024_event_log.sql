-- ADR-039 / issue #33: the replicated off-chain data plane's authoritative
-- signed event log. Generalizes migration 000016's metering_evidence
-- pattern (append-only, per-subject-sequenced, Ed25519-signed) from a
-- single subject class (metering) to every workload-lifecycle transition
-- internal/orchestrator/worker.go and internal/workloadapi/postgres.go
-- already drive today -- see ADR-039 Decision §1/§2/§11 for the full
-- reasoning. This migration adds no new database engine: event_log lives
-- on the same Postgres instance as workloads/metering_evidence, is
-- insert-only (nothing in internal/eventlog ever UPDATEs or DELETEs a row
-- here except the governed pruning path in §8, which only ever DELETEs
-- rows already superseded by an independently witnessed snapshot), and is
-- dual-written alongside workloads in the same transaction, never
-- replacing it (ADR-039 §11 -- this PR is additive, not a cutover).
--
-- Three properties this schema enforces structurally, mirroring
-- metering_evidence's own three (000016's header comment):
--
--   1. "deterministic event IDs, ordering, idempotence" -- event_id is a
--      sha256 over a canonical, hand-rolled byte encoding (internal/
--      eventlog's CoreBytes, mirroring internal/metering/signing.go's
--      signedBytes -- never a proto marshal, ADR-039 §1), computed
--      identically by every independent replica that receives the same
--      event; UNIQUE(subject_type, subject_id, sequence) is the hard
--      idempotence gate a duplicate append is rejected against (ADR-039
--      §4), the identical shape metering_evidence's own
--      UNIQUE(provider_id, workload_id, sequence) already established.
--   2. "hash-chained ordering, tamper-evident" -- prev_event_hash links
--      each subject's own sequence, scoped per-subject (not globally)
--      exactly like metering_evidence_workload_idx's own per-workload
--      scoping (ADR-039 §2).
--   3. "quarantine, never silently drop" -- event_log_rejections is the
--      direct, generalized analog of metering_evidence_rejections: an
--      append-only audit trail of every submission that failed hash-chain,
--      signature, or chain-anchor verification, never joined into
--      anything authoritative (ADR-039 §6).
--
-- event_log_witness_acks is new relative to metering_evidence's precedent:
-- ADR-039 §8's pruning rule ("never for a subject whose terminal snapshot
-- has not yet been independently verified by at least one witness beyond
-- the Control Plane itself") needs somewhere to record that an external
-- witness actually verified a given SNAPSHOT event before internal/
-- eventlog's pruning path is allowed to delete anything superseded by it.
CREATE TABLE IF NOT EXISTS event_log (
    -- sha256("openinfra-eventlog-v1\x00" || subject_type || ...), computed
    -- by internal/eventlog.CoreBytes/EventID -- see that package's doc
    -- comment for the exact byte layout (ADR-039 §1).
    event_id bytea PRIMARY KEY CHECK (octet_length(event_id) = 32),
    subject_type text NOT NULL CHECK (subject_type IN ('WORKLOAD_LIFECYCLE', 'LEASE_CORRELATION', 'METERING_EVIDENCE')),
    -- workload_id (as UTF-8 bytes of its UUID text form) for
    -- WORKLOAD_LIFECYCLE/LEASE_CORRELATION; provider_id||workload_id for
    -- METERING_EVIDENCE once that subject class is wired to this log (not
    -- this PR -- see internal/eventlog's doc comment for scope).
    subject_id bytea NOT NULL CHECK (octet_length(subject_id) BETWEEN 1 AND 256),
    sequence bigint NOT NULL CHECK (sequence > 0),
    -- All-zero for sequence = 1 (ADR-039 §2's "zero for sequence=1").
    prev_event_hash bytea NOT NULL CHECK (octet_length(prev_event_hash) = 32),
    event_type text NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
    -- Plaintext for operational metadata; ciphertext + wrapped-DEK blob for
    -- any genuinely tenant-private field (ADR-039 §7 -- no field in this
    -- codebase's wire protocol is tenant-private today, so every payload
    -- this PR ever writes is plaintext operational metadata; §7's envelope-
    -- encryption mechanism is structural only, exercised by
    -- eventlog_encryption_test.go, not yet invoked by any real write path).
    payload bytea NOT NULL,
    payload_hash bytea NOT NULL CHECK (octet_length(payload_hash) = 32),
    -- Both NULL or both set (ADR-039 §5): NULL exclusively for the
    -- honestly-named pre-lease gap (a WORKLOAD_LIFECYCLE subject's very
    -- first event, before AssignLease has produced a real lease_id).
    chain_anchor_lease_id bigint CHECK (chain_anchor_lease_id IS NULL OR chain_anchor_lease_id >= 0),
    chain_anchor_block_hash bytea CHECK (chain_anchor_block_hash IS NULL OR octet_length(chain_anchor_block_hash) = 32),
    CHECK ((chain_anchor_lease_id IS NULL) = (chain_anchor_block_hash IS NULL)),
    -- Raw 32-byte Ed25519 public key: either a registered provider's
    -- identity key (verified against pallet-provider-registry's
    -- Provider.public_key by a witness) or the Control Plane's own bridge-
    -- account key (blockchainbridge.Registrar.Account(), ADR-039 §3) --
    -- the same two signers this codebase already trusts, no new key type.
    signer_public_key bytea NOT NULL CHECK (octet_length(signer_public_key) = 32),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    -- Informational only -- never the ordering key (ADR-012 §4, ADR-039
    -- §2's "recorded_at... participates in no ordering decision").
    recorded_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (subject_type, subject_id, sequence)
);

CREATE INDEX IF NOT EXISTS event_log_subject_idx ON event_log (subject_type, subject_id, sequence);
-- Backs catch-up export (ADR-039 §10's SubscribeEvents(subject_type,
-- since_sequence)) and the pruning path's snapshot lookup, both of which
-- scan forward by recorded order within a subject_type without needing to
-- know every subject_id in advance.
CREATE INDEX IF NOT EXISTS event_log_subject_type_recorded_idx ON event_log (subject_type, recorded_at);

-- Append-only audit trail of every event this Control Plane, or any
-- witness replaying internal/eventlog.VerifyChain, refused to accept into
-- an authoritative projection: a hash-chain break, a signature that does
-- not verify against the claimed signer_public_key, a chain_anchor that
-- does not correspond to a real finalized on-chain fact, or a duplicate/
-- stale sequence. Deliberately has no foreign key to event_log (a rejected
-- submission's own event_id may never be computable if its fields are
-- malformed) and every column below is nullable except reason, mirroring
-- metering_evidence_rejections' identical looseness for the identical
-- reason (ADR-039 §6).
CREATE TABLE IF NOT EXISTS event_log_rejections (
    rejection_id uuid PRIMARY KEY,
    subject_type text,
    subject_id bytea,
    sequence bigint,
    event_id bytea,
    reason text NOT NULL,
    detail text,
    received_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS event_log_rejections_subject_idx ON event_log_rejections (subject_type, subject_id, received_at);

-- One row per (event_id, witness) acknowledgement that an independently-
-- operated witness (ADR-039 §9 -- a process with no special relationship
-- to the Control Plane beyond read access to the export stream and a
-- chain node) has itself replayed and verified a SNAPSHOT event's hash
-- chain, signature, and chain anchor. internal/eventlog's pruning path
-- (§8) requires at least one row here for a subject's terminal SNAPSHOT
-- before deleting anything that snapshot supersedes -- the structural
-- guard against "prune, then claim the pruned history said whatever is
-- convenient" ADR-039 §8 names explicitly. witness_public_key is
-- self-asserted by whichever witness calls RecordWitnessAck (this PR does
-- not implement witness identity/reputation -- see ADR-039's own
-- "malicious witness" threat-model entry, out of scope for this table to
-- solve) and is therefore evidence a witness *claimed* to verify, not
-- proof no witness could lie; it is never treated as more than that by any
-- caller in this PR.
CREATE TABLE IF NOT EXISTS event_log_witness_acks (
    event_id bytea NOT NULL REFERENCES event_log (event_id),
    witness_public_key bytea NOT NULL CHECK (octet_length(witness_public_key) = 32),
    acked_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, witness_public_key)
);

-- Carries the finalized block hash observed the moment a workload's lease
-- was first confirmed Active (internal/orchestrator/worker.go's
-- LEASE_PENDING case, EnsureLeaseActive's FinalizedLease.
-- FinalizedBlockHash) forward onto every later event_log entry for that
-- same workload (DEPLOYING, RUNNING, STOPPED, FAILED, RETRY), so each of
-- those events' chain_anchor references the same already-finalized
-- LeaseCreated/LeaseStateChanged fact without a fresh chain read per
-- event (ADR-039 §5's ChainAnchor{lease_id, block_hash}, computed once at
-- MarkLeased and read back from this column by every subsequent Mark*
-- call rather than re-derived). NULL exactly when lease_id is NULL --
-- before AssignLease/MarkLeased, there is no chain fact yet to anchor
-- against (ADR-039 §5's honestly-named pre-lease gap).
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS lease_block_hash bytea CHECK (lease_block_hash IS NULL OR octet_length(lease_block_hash) = 32);
