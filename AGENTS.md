# OpenInfra Network — Repository Instructions

## Vision and MVP

OpenInfra Network is a decentralized provider-cloud prototype. The MVP must join a Provider Agent to the Control Plane, validate its identity, persist the provider in PostgreSQL, cache heartbeats in Redis, and expose it as `ACTIVE` before accepting a first workload.

## Frozen Architecture

- `provider-agent/`: Rust, Tokio, tonic/prost, bollard, sysinfo, tracing, Ed25519, embedded local state.
- `control-plane/`: Go API, Agent Manager, Scheduler, Blockchain Bridge, orchestrator, PostgreSQL, and reconstructible Redis caches.
- `blockchain/`: deterministic Rust/Substrate runtime for registry, offers, leases, reputation, rewards, and availability.
- `protocol/proto/`: versioned Protobuf source of truth for all network contracts.
- `deployments/`: reproducible local environment; `tests/`: cross-component integration and E2E tests.

Do not change a language, framework, database, or component boundary without an accepted ADR. Components must not take over another component’s responsibilities. The Provider Agent never talks directly to the blockchain in the MVP.

## Integration and Contract Rules

Generated Go and Rust types must derive from Protobuf; do not add manual copies. Before changing a `.proto`, identify every consumer, preserve wire compatibility, run breaking-change checks, regenerate both languages, and update tests and docs. PostgreSQL is authoritative off-chain; Redis contains only reconstructible state. Never report `RUNNING`, a successful deployment, or an on-chain transition before receiving authoritative confirmation.

## Security

Never commit or log secrets, private keys, session tokens, or credentials. Validate external input, use mTLS between Control Plane and Agent, bound retries and timeouts, and make operations idempotent. Docker workloads require CPU/memory/PID quotas, `no-new-privileges`, a maximum workload count, and persistent workload-to-container mapping. Substrate code must avoid floats, network/system access, unbounded data, unchecked arithmetic, and unauthorized state changes.

## Working Method

Inspect applicable documentation and local `AGENTS.md`, propose the smallest coherent change, and add success and failure tests. Do not hide errors, ship silent mocks, or use placeholder success paths. Sub-agents may analyze independently but must not edit the same files concurrently; the primary thread owns integration and final verification.

## Global Commands

Use `make fmt`, `make lint`, `make test`, or component targets documented by `make help`. A command is successful only when it was actually executed. Missing manifests and tools are blockers to document, never reasons to substitute the stack.

## Prohibited Changes

Do not introduce Kubernetes, another database, direct Agent-to-chain access, runtime orchestration, detailed on-chain metrics, hard-coded secrets, or contract changes without consumer analysis. Every production feature requires tests and every architecture change requires an ADR.
