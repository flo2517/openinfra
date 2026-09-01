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

## Staged Architecture

The architecture above is frozen for the current stage, not forever. [ADR-012](docs/adr/012-decentralization-roadmap-and-trust-boundaries.md) defines the decentralization roadmap, the trust and threat model for every role, the per-class data classification, and the staged migration from today's single Control Plane to a decentralized network. Its §6 names the specific follow-up ADR that each later stage requires. A prohibition below is lifted only by accepting the ADR named there — never by an implementation deciding the change is small.

## Integration and Contract Rules

Generated Go and Rust types must derive from Protobuf; do not add manual copies. Before changing a `.proto`, identify every consumer, preserve wire compatibility, run breaking-change checks, regenerate both languages, and update tests and docs. PostgreSQL is authoritative off-chain; Redis contains only reconstructible state. Never report `RUNNING`, a successful deployment, or an on-chain transition before receiving authoritative confirmation.

## Security

Never commit or log secrets, private keys, session tokens, or credentials. Validate external input, use mTLS between Control Plane and Agent, bound retries and timeouts, and make operations idempotent. Docker workloads require CPU/memory/PID quotas, `no-new-privileges`, a maximum workload count, and persistent workload-to-container mapping. Substrate code must avoid floats, network/system access, unbounded data, unchecked arithmetic, and unauthorized state changes.

## Working Method

Inspect applicable documentation and local `AGENTS.md`, propose the smallest coherent change, and add success and failure tests. Do not hide errors, ship silent mocks, or use placeholder success paths. Sub-agents may analyze independently but must not edit the same files concurrently; the primary thread owns integration and final verification.

## Global Commands

Use `make fmt`, `make lint`, `make test`, or component targets documented by `make help`. A command is successful only when it was actually executed. Missing manifests and tools are blockers to document, never reasons to substitute the stack.

## Prohibited Changes

Every production feature requires tests and every architecture change requires an ADR.

**Permanent — no ADR lifts these.** Never hard-code secrets. Never change a contract without consumer analysis. Never put detailed metrics on-chain. Never put tenant payloads, logs, secrets, or any personal data on-chain: consensus state cannot be erased, so only hashes and commitments may cross that line (ADR-012 §3).

**Prohibited until the ADR gate named in ADR-012 §6 is accepted.** Do not introduce another database (ADR-024, ADR-021), direct Agent-to-chain access (ADR-020), runtime orchestration (ADR-019 — accepted as ADR-038 for issue #50 and #62's provider-reselection slice only; #62's failure-detection/fencing/migration-retry scope still needs its own follow-up ADR), decentralized storage (ADR-021 — accepted as ADR-037 for issue #35's static-frontend-assets slice only; #58/#59's broader object/block storage still need their own ADR before that prohibition lifts for them), a TEE trust root (ADR-022), or a replacement for `EnsureRoot` governance (ADR-023). Kubernetes remains prohibited under ADR-006, which fixes Docker as the runtime; adopting it needs its own accepted ADR.
