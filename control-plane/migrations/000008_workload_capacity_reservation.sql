-- Reservation columns let AssignLease check "does this provider still have
-- headroom" with a pure SQL SUM instead of decoding every open workload's
-- protobuf definition inside the commit transaction. Populated once, from
-- validated ResourceRequirements, when the row is created; never
-- recomputed, so a workload's claim on its provider never drifts while
-- open. CPU is stored as millicores (requirements.Cpu * 1000, rounded) to
-- keep the reservation ledger integer-only.
ALTER TABLE workloads
    ADD COLUMN IF NOT EXISTS reserved_cpu_millicores integer NOT NULL DEFAULT 0
        CHECK (reserved_cpu_millicores >= 0),
    ADD COLUMN IF NOT EXISTS reserved_ram_mb bigint NOT NULL DEFAULT 0
        CHECK (reserved_ram_mb >= 0),
    ADD COLUMN IF NOT EXISTS reserved_storage_gb bigint NOT NULL DEFAULT 0
        CHECK (reserved_storage_gb >= 0);

-- Sums this index over "open, provider-assigned" workloads on every
-- AssignLease attempt; partial + covering keeps that SUM cheap regardless
-- of how many COMPLETED/FAILED rows accumulate.
CREATE INDEX IF NOT EXISTS workloads_provider_reservation_idx
    ON workloads (provider_id)
    INCLUDE (reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb)
    WHERE state IN ('LEASE_PENDING', 'LEASED', 'DEPLOYING', 'RUNNING');
