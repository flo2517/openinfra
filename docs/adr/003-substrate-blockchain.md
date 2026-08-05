# ADR-003: Substrate for the Blockchain

**Status:** Accepted

## Context

Provider identity, offers, leases, reputation, availability, and Reward Points require deterministic shared state and upgradeable domain modules.

## Decision

Use a Rust/Substrate runtime with six MVP pallets: provider registry, resource market, lease, reputation, rewards, and availability.

## Consequences

Runtime code forbids floats and external I/O, bounds storage, checks arithmetic, enforces origins, and uses benchmarked weights. Operational detail stays off-chain.
