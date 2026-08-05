# ADR-008: On-Chain and Off-Chain Boundaries

**Status:** Accepted

## Context

Consensus state must remain compact and deterministic, while orchestration needs detailed and rapidly changing operational data.

## Decision

Keep provider network identity, offers, leases, validated availability, reputation, and Reward Points on-chain. Keep users, workload requests, orchestration history, metrics, logs, Docker state, and secrets off-chain. PostgreSQL is authoritative off-chain; Redis is reconstructible.

## Consequences

Only the Control Plane bridge talks to Substrate in the MVP. Events correlate both sides, and neither side may infer success before authoritative confirmation.
