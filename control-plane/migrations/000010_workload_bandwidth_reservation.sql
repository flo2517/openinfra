-- Extends 000008's reservation ledger to a fourth/fifth dimension: issue
-- #30 treats bandwidth as a first-class, schedulable, overcommit-checked
-- resource the same way CPU/RAM/storage already are. Units match
-- protocol/proto's Bandwidth message exactly (megabits per second).
-- Populated once, from validated ResourceRequirements.bandwidth, when the
-- row is created; a workload with no bandwidth requirement gets 0/0,
-- which never contributes to AssignLease's capacity check (see fitBps's
-- "a zero requirement is always satisfied" convention in
-- internal/scheduler/rank.go).
ALTER TABLE workloads
    ADD COLUMN IF NOT EXISTS reserved_ingress_mbps bigint NOT NULL DEFAULT 0
        CHECK (reserved_ingress_mbps >= 0),
    ADD COLUMN IF NOT EXISTS reserved_egress_mbps bigint NOT NULL DEFAULT 0
        CHECK (reserved_egress_mbps >= 0);

-- Replaces 000008's index with one that also covers the new columns --
-- AssignLease's SUM query reads all five reserved_* columns in one pass,
-- so the covering index must too, or Postgres falls back to a heap fetch
-- per row under load.
DROP INDEX IF EXISTS workloads_provider_reservation_idx;
CREATE INDEX IF NOT EXISTS workloads_provider_reservation_idx
    ON workloads (provider_id)
    INCLUDE (reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb, reserved_ingress_mbps, reserved_egress_mbps)
    WHERE state IN ('LEASE_PENDING', 'LEASED', 'DEPLOYING', 'RUNNING');
