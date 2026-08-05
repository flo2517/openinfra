# Roadmap

## v0.1 — Provider Join and First Workload

Deliver the MVP in this dependency order:

1. make Provider Join transactional on-chain and expose `ACTIVE` only after confirmation;
2. secure and persist the Provider Agent Docker executor;
3. run one Control Plane-to-Agent workload lifecycle;
4. require an authorized on-chain lease before deployment;
5. add WireGuard for private workload networking;
6. collect bounded proofs and metrics for availability and reputation.

The detailed entry conditions, exit criteria, and failure rules are documented in
[`docs/milestones/mvp-integration-sequence.md`](docs/milestones/mvp-integration-sequence.md).

## v0.2 — Availability and Reputation

Add bounded Proof of Availability, heartbeat expiry, vector reputation updates, metrics summaries, failure handling, and integration tests across Agent, Control Plane, and chain.

## v0.3 — Leases and Rewards End-to-End

Complete authorized lease transitions, controlled reward arithmetic, event correlation, idempotent orchestration, recovery from partial failures, and multi-component observability.

## v1.0 — Stable Multi-Provider Network

Harden multi-provider operation, upgrades, migrations, security, performance, reliability, compatibility, and operational documentation. Production readiness requires independent security review and measurable SLOs.
