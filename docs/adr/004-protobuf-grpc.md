# ADR-004: Protobuf and gRPC

**Status:** Accepted

## Context

Rust and Go services require compatible, versioned, strongly typed interfaces.

## Decision

Use Protobuf files in `protocol/proto/` as the sole network-contract source and gRPC with mTLS for Control Plane–Agent communication.

## Consequences

Generate both language bindings, validate compatibility with Buf, reserve removed fields, and coordinate every breaking change across consumers.
