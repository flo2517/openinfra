# MVP Integration Sequence

This sequence is the implementation order for the first end-to-end OpenInfra flow. A stage starts only when the previous stage's exit criteria pass in automated tests.

## 1. Transactional Provider Join

The Agent proves ownership of its Ed25519 identity to the Control Plane. PostgreSQL records the request as `PENDING`; the Blockchain Bridge submits an idempotent registration and waits for finalized chain state. Only then may PostgreSQL and heartbeat responses expose the provider as `ACTIVE`. Retries must recover safely after RPC, process, or database failures.

Exit: one signed join is visible in PostgreSQL, Redis, and `provider-registry`; duplicate requests produce one logical registration.

## 2. Secured Docker Executor

The Agent implements Docker through a trait-backed executor and persists `workload_id -> container_id`. Every workload has CPU, memory, and PID limits plus `no-new-privileges`; starts and stops are reported only after Docker confirms them.

Status: implemented and validated against a local Docker daemon. Remaining hardening is labeled-orphan adoption/quarantine for the narrow crash window between container creation and mapping persistence.

Exit: unit and Docker integration tests cover create, start, inspect, stop, restart recovery, invalid images, quota rejection, and daemon failure.

## 3. First Workload Lifecycle

The Control Plane calls the authenticated Agent gRPC API with bounded deadlines, retries, and correlation IDs. PostgreSQL owns orchestration state; Agent observations drive state transitions.

Exit: an E2E test reaches `RUNNING`, then `STOPPED`, and verifies failure and retry paths without false success.

## 4. Lease Authorization

The Blockchain Bridge creates or observes a lease and waits for finalized authorization before dispatch. The runtime remains deterministic and never orchestrates Docker.

Exit: the workload is rejected without a valid lease and accepted exactly once with one.

Status: implemented for the local MVP. The Control Plane persists provider and numeric lease mapping, verifies the exact `Active` lease at a finalized Substrate head, dispatches over identity-checked mTLS, and commits `RUNNING` only after the Agent confirms Docker state.

## 5. WireGuard Networking

WireGuard is introduced after workload identity and lease authorization are stable. The Control Plane allocates short-lived peer configuration; the Agent configures only its assigned peer and never logs private keys. Docker workloads attach to a constrained network namespace. Key rotation, revocation, port conflicts, and cleanup are tested.

Exit: two authorized endpoints communicate over the overlay; revoked or expired peers cannot communicate; teardown removes network state.

## 6. Proofs, Metrics, and Reputation

The Agent emits bounded local proofs and Prometheus metrics. The Control Plane validates and summarizes them; only consensus-relevant aggregates reach the chain.

Exit: availability and reputation updates are deterministic, bounded, attributable, and tested against replay and malformed evidence.

## Cross-Cutting Gate

Each stage requires documented configuration, no committed secrets, healthchecks, repeatable Compose setup, component tests, and an E2E failure scenario. Protocol or architecture changes require consumer analysis and an accepted ADR before implementation.
