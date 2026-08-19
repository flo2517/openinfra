-- ADR-025 §2: per-workload cumulative bandwidth usage, self-reported by
-- the Agent over the existing heartbeat path. `WorkloadBandwidthUsage`
-- has no signature field of its own (see its proto doc comment) -- it
-- lives inside HeartbeatSigningPayload, so it is covered by that
-- heartbeat's one Ed25519 signature, verified before RecordUsage is ever
-- called (see internal/providerjoin's ReportHeartbeat).
--
-- Not billing-grade telemetry (ADR-025 §2's own "What this is not"): this
-- table stores exactly one row per (provider, workload) -- the latest-
-- known cumulative counters and when they were last seen. No history, no
-- persisted deltas, no aggregation. Good enough for capacity planning and
-- spotting workloads that persistently exceed their reservation;
-- anything billing-adjacent is explicitly deferred to the v1.1 metering
-- work (issue #19/#21).
-- workload_id references workloads(workload_id) -- workload_bandwidth
-- rides inside the already-authenticated heartbeat, so a validly-signed
-- but buggy/compromised Agent could otherwise report usage for a
-- syntactically-valid but nonexistent workload forever. The actual
-- filtering happens in RecordUsage's own query (an INNER JOIN against
-- workloads that silently excludes anything that doesn't match, so one
-- bad workload_id among several never blocks the others) -- this FK is
-- defense in depth against any future write path that bypasses that
-- query, not the primary mechanism. workloads rows are never deleted
-- (terminal states are COMPLETED/FAILED, not removed), so this FK never
-- fails for a workload that legitimately existed.
CREATE TABLE IF NOT EXISTS workload_bandwidth_usage (
    provider_id text NOT NULL REFERENCES providers (provider_id),
    workload_id uuid NOT NULL REFERENCES workloads (workload_id),
    ingress_bytes_total bigint NOT NULL CHECK (ingress_bytes_total >= 0),
    egress_bytes_total bigint NOT NULL CHECK (egress_bytes_total >= 0),
    -- When the Agent's counters started accumulating -- i.e. when the
    -- container the Agent has running now was (re)started. A change from
    -- the stored value tells RecordUsage the counters were reset by a
    -- restart, so the incoming reading starts a new series rather than
    -- being a suspicious decrease to discard.
    window_started_at timestamptz NOT NULL,
    last_reported_at timestamptz NOT NULL,
    PRIMARY KEY (provider_id, workload_id)
);
