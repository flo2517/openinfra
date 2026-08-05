# ADR-001: Rust for the Provider Agent

**Status:** Accepted

## Context

The edge agent handles untrusted workload input, cryptographic identity, concurrent RPCs, hardware inspection, and Docker lifecycle operations.

## Decision

Implement the Provider Agent in Rust using Tokio, tonic/prost, bollard, sysinfo, tracing, Ed25519, and an approved embedded store.

## Consequences

Memory safety and explicit error handling support the host trust boundary. Contributors must maintain a Rust workspace and generated Protobuf types. The Agent does not access Substrate directly in the MVP.
