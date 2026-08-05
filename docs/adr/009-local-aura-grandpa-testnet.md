# ADR-009: Aura/GRANDPA Local Testnet and Governance Boundary

**Status:** Accepted

## Context

The original node used single-process manual sealing and immediate finalization. That topology cannot test authority discovery, peer synchronization, loss of an author, or network finality. Development sudo also must not be mistaken for shared-network governance.

## Decision

Use Aura block production and GRANDPA finality for the reproducible local multi-node testnet. Genesis contains two deterministic development authorities (Alice and Bob); a third full node observes and verifies finality. The generated Control Plane bridge account remains the sudo key only in `Development` and `Local` chain types so existing MVP extrinsic flows remain testable.

Development keyring identities, sudo, and loopback RPC are forbidden for shared, staging, and production-like networks. A future production chain specification requires independently managed authority keys and a separate accepted ADR defining multisignature or collective governance, key rotation, validator admission, slashing, and runtime upgrades. Until then this testnet must not be exposed beyond a developer machine.

## Consequences

Cross-node synchronization and finalized-state behavior can be validated locally. Runtime specification version 3 adds Aura and GRANDPA without changing existing business-pallet call indices. This decision does not claim production decentralization or remove the need for benchmarked weights and operational key management.
