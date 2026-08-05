# ADR-007: Proof of Availability for the MVP

**Status:** Accepted

## Context

The network needs a bounded first signal that providers remain reachable without placing detailed telemetry or external checks inside consensus.

## Decision

Use signed, replay-resistant availability challenges summarized through controlled on-chain submissions. Defer general proof-of-compute and proof-of-storage schemes.

## Consequences

The Control Plane coordinates challenges; the runtime validates authorized deterministic summaries. Timeouts, replay handling, units, and retention require tests.
