# Roadmap

This file and the GitHub milestones are the authoritative roadmap. `architecture.md` and
`architecture_review.md` §7 contain an older, conflicting version numbering and are aspirational
documents, not a record of what is planned or implemented.

Milestones v3.0 and later are staged and gated by
[ADR-012](docs/adr/012-decentralization-roadmap-and-trust-boundaries.md), which defines the trust
boundaries, the data classification, and the follow-up ADR each stage requires. No implementation
in those milestones starts before its gate ADR is accepted.

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

## v0.3 — Leases and Rewards E2E

Complete authorized lease transitions, controlled reward arithmetic, event correlation, idempotent orchestration, recovery from partial failures, and multi-component observability.

## v1.0 — Stable Multi-Provider Network

Harden multi-provider operation, upgrades, migrations, security, performance, reliability, compatibility, and operational documentation. Production readiness requires independent security review and measurable SLOs.

## v1.1 — Metering and Settlement

Add auditable usage metering, billing, escrow, settlement, and provider payouts after the stable MVP. Issues: #19 (metering and settlement architecture), #20 (usage metering and invoice ledger), #21 (on-chain escrow and provider settlement). #19 also gates streaming payments (#51) in v3.0.

## v2.0 — OpenStack Compatibility

Expose an OpenStack-compatible cloud surface backed by OpenInfra providers, including VM, identity, networking, storage, images, and Kubernetes integration. Issues: #22 (service mapping), #23 (Keystone identity), #24 (Nova/Placement), #25 (Neutron networking), #26 (Glance/Cinder), #27 (Kubernetes).

This is an API-surface track, orthogonal to the decentralization stages below: it is neither blocked by them nor a prerequisite for them, provided it introduces no new central authority. Kubernetes (#27) needs its own ADR — ADR-006 currently fixes Docker as the runtime.

## v3.0 — Decentralized Control Plane and Data

Progressively remove centralized frontend, database, scheduler, and operational trust assumptions while preserving privacy, consistency, and recoverability. This is Stage 1 of ADR-012 §5: decentralize *authority*, while the data plane stays as it is.

| Issue | Gate |
|---|---|
| #32 — decentralization roadmap and trust boundaries | ADR-012 (accepted) |
| #33 — replicated off-chain data plane | ADR-013 |
| #34 — multiple Control Planes and scheduling relays | ADR-014 |
| #35 — content-addressed frontend distribution | ADR-018 |
| #36 — decentralized identity, governance, validator operations | ADR-020 |
| #50 — orchestration in smart contracts | ADR-016 |
| #51 — streaming payments | #19 (v1.1), no new ADR |
| #52 — slashing for availability guarantees | ADR-015 (accepted); also depends on #36, and requires provider bonding first |

## v4.0 — P2P Mesh & Global Fabric

Full P2P WireGuard mesh, DHT discovery, Virtual VPC and decentralized ingress/DNS. Stage 2 of ADR-012 §5: remove the Control Plane from the packet path. Depends on #36, because peer authentication cannot rest on a Control-Plane-issued allowlist once the Control Plane is no longer in the path.

Issues #53 (P2P mesh), #54 (gateway nodes), #55 (decentralized DNS) — all gated by ADR-017.

## v5.0 — Geo-Distributed Economy & Storage

Geo-discovery, Proof of Resource (PoR), and decentralized S3/block storage. Stage 3 of ADR-012 §5: remove the Control Plane from discovery and make storage a first-class verified resource.

| Issue | Gate |
|---|---|
| #56 — DHT geo-discovery | ADR-017 |
| #57 — Proof of Resource | none; extends ADR-007 and ADR-011 §3 |
| #58 — S3-compatible object storage | ADR-018 |
| #59 — replicated block volumes | ADR-018 |

## v6.0 — Confidential Cloud & Auto-Healing

TEE support, distributed attestation, auto-migration and P2P IaC. Stage 4 of ADR-012 §5: close the operator-collusion gap and remove human intervention from failure recovery.

| Issue | Gate |
|---|---|
| #60 — TEE support (Intel SGX / AMD SEV) | ADR-019 |
| #61 — distributed enclave attestation | ADR-019 |
| #62 — auto-healing and workload migration | ADR-016 |
| #63 — infrastructure topology DSL | none while evaluated off-chain; ADR-016 if evaluated on-chain |
