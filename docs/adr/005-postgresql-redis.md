# ADR-005: PostgreSQL and Redis

**Status:** Accepted

## Context

Critical orchestration state needs transactions and recovery, while heartbeats and short-lived rankings need low-latency access.

## Decision

Use PostgreSQL as the off-chain source of truth and Redis only for reconstructible heartbeats, caches, rankings, and short locks.

## Consequences

No critical state may exist only in Redis. Cache loss must be recoverable from PostgreSQL, agents, or blockchain events.
