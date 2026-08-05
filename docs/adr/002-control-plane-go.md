# ADR-002: Go for the Control Plane

**Status:** Accepted

## Context

The Control Plane coordinates APIs, agents, persistence, scheduling, and blockchain access with extensive concurrent I/O.

## Decision

Implement the Control Plane and Scheduler in Go, using generated gRPC clients and standard context cancellation.

## Consequences

Domain boundaries remain explicit and operations must be idempotent, timed out, observable, and persisted. Substrate-specific logic stays in the Blockchain Bridge.
