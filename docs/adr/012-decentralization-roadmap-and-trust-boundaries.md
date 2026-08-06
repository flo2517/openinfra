# ADR-012: Decentralization roadmap and trust boundaries

## Status

Accepted.

## Context

OpenInfra's stated goal is a decentralized provider cloud — general infrastructure
(CPU, RAM, storage, bandwidth) traded and verified the way Bittensor trades and
verifies machine-learning work, without the restriction to a single workload
class. The GitHub milestones now describe that path end to end (v0.1 through
v6.0), but the repository cannot legally execute on any of it.

`AGENTS.md`'s "Prohibited Changes" section forbids "another database, direct
Agent-to-chain access, runtime orchestration" in absolute terms
(`AGENTS.md:35`), and its frozen-architecture rule forbids changing "a language,
framework, database, or component boundary without an accepted ADR"
(`AGENTS.md:15`). Those two rules are correct — they are what has kept the MVP
coherent — but between them they block every issue in milestones v3.0 through
v6.0: on-chain orchestration (#50), a WireGuard mesh with no central
configuration server (#53), DHT-based discovery (#56), a replicated off-chain
data plane (#33), and decentralized object and block storage (#58, #59). The
escape hatch is "every architecture change requires an ADR", and there is no ADR
to point at. Issue #32 asks for exactly this document and states that "no
architecture implementation starts before ADR acceptance."

Decentralization is also not a single switch. Today every authoritative fact
about a provider passes through one operator: PostgreSQL is the sole off-chain
authority (ADR-005), a single Control Plane bridge account holds the root origin
for provider registration and lease management (`blockchain/runtime/src/lib.rs:160-161,208`),
and until ADR-011 the same account also produced every reputation number.
ADR-011 moved availability and reputation writes to signed, stake-bonded Network
Validators (`blockchain/runtime/src/lib.rs:219,241`) — the first genuine removal
of a central trust assumption, and the template for the rest. What is missing is
the map: which remaining facts move where, in what order, under which threat
model, and what may never move on-chain at all.

This ADR is that map. It does **not** authorize any implementation by itself.

## Decision

### 1. Vocabulary

Issue #32 and the architecture documents use overlapping names for different
things. These are the definitions this repository uses from here on.

| Term | Definition |
|---|---|
| **Worker** / **Provider** | The same entity: an operator running a Provider Agent that advertises and delivers CPU/RAM/storage/network. ADR-011 says "Worker" when it means "the provider being scored". |
| **Network Validator** | A stake-bonded, independently operated product role that challenges Workers, evaluates delivered service, and submits attributable weights on-chain (ADR-011). Not a block producer. |
| **Chain Authority** | An Aura block producer / GRANDPA finality voter that keeps the chain live (ADR-009). Not a Network Validator. The two roles are deliberately separable and must never be conflated in code, docs, or metrics. |
| **Control Plane replica** | One independently operated instance of the Go Control Plane. Today there is exactly one and it is trusted; #34 makes replicas plural. |
| **Gateway node** | A node that terminates public ingress and routes into the private workload mesh (#54). Introduced at Stage 2; does not exist today. |
| **Storage node** | A node providing content-addressed object storage or replicated block volumes (#58, #59). Introduced at Stage 3; does not exist today. |
| **Tenant** / **User** | The party submitting a workload and owning its data and secrets. Has no on-chain identity today. |
| **Governance** | Whatever origin may change runtime parameters, suspend a validator, or authorize a runtime upgrade. Today this is `EnsureRoot` (`blockchain/runtime/src/lib.rs:316`), i.e. one sudo key. #36 replaces it. |

### 2. Trust and threat model

For each role: what it may assert, what the system trusts it for, what it must
never be trusted for, and how it fails when adversarial.

| Role | May assert | Trusted for | Never trusted for | Adversarial modes |
|---|---|---|---|---|
| Worker | Its own inventory, its own challenge responses, container state | Nothing on its own — every claim it makes is either verified by a challenge or irrelevant | Its own reputation, its own availability, its own resource truth | Over-advertising capacity; forging challenge responses; going silent after payment; running the same hardware behind many identities (Sybil) |
| Network Validator | A signed score for a Worker it was assigned to, plus a hash of the underlying evidence | Producing one attributable weight per assigned round | Being the sole input to any score; scoring itself; scoring outside its committee | Collusion with a Worker; weight-copying from other validators; withholding submissions to degrade quorum; bribery |
| Chain Authority | Block production and finality votes | Liveness and ordering only | Any product-level judgement about a Worker | Censoring extrinsics; equivocation; halting finality |
| Control Plane replica | Off-chain orchestration state, workload lifecycle transitions | Stage 0: authoritative off-chain state. Stage 1+: one candidate view, reconciled against finalized chain facts | Being the sole authority for anything a tenant or provider depends on financially | Under/over-reporting its own providers; silently dropping commands; replaying or reordering state transitions; unilateral censorship of a tenant |
| Gateway node | Public routing for workloads that opted in | Reachability | Confidentiality or integrity of tenant traffic — traffic must be end-to-end protected through it | Traffic interception; selective blackholing; metadata harvesting |
| Storage node | Possession of a content-addressed blob or block replica | Serving bytes that match their advertised hash | Retention without a proof, or confidentiality without client-side encryption | Silent data loss; claiming storage it does not hold; correlating tenants by access pattern |
| Tenant | Its workload definition, its own signatures | Authorizing its own workloads and paying for them | Any claim about a provider's delivered service | Non-payment; abusive workloads; forged lease claims |
| Governance | Parameter changes, suspensions, runtime upgrades | Bounded, timelocked, auditable emergency action | Silent or instant changes to economics, origins, or upgrade paths | Capture by a single operator; rushed upgrade bypassing timelock; targeted suspension as censorship |

Two threats cut across every role and are **not solved** by this ADR:

- **Operator-level collusion.** Distinct `AccountId`s controlled by one human are
  indistinguishable on-chain. ADR-011 §4 already flags this as an accepted gap,
  mitigated only by bonded stake and quorum. Nothing below changes that; it needs
  the slashing ADR (§6) and, ultimately, attestation (#60, #61).
- **Bootstrap centralization.** Every stage below has a period where too few
  independent parties exist for its own quorum assumptions to hold. Each stage
  must therefore state its degraded-quorum behavior and report it honestly rather
  than reporting false success — the rule already in `AGENTS.md:19`.

### 3. Data classification

The central table. Placement classes are: **on-chain** (consensus state),
**content-addressed** (immutable, hash-named, replicated by any node),
**replicated** (mutable, multi-writer off-chain state), **encrypted** (at rest
and in transit, keyed by the data owner), **cached** (reconstructible, never
authoritative), **local-only** (never leaves the node).

| Data class | Integrity need | Availability need | Privacy | Retention | Stage 0 placement (today) | Target placement |
|---|---|---|---|---|---|---|
| Node identity (public keys, accounts) | Consensus | Highest | Public | Permanent | On-chain (`pallet-provider-registry`, `pallet-network-validator`) | Unchanged |
| Private keys | Absolute | Node-local | Secret | Until rotated | Local-only (`agent-core::identity`) | Local-only — **never** replicated, never escrowed |
| Offers / advertised capacity | Consensus | High | Public | Current + bounded history | On-chain (`pallet-resource-market`) | Unchanged |
| Leases | Consensus | Highest | Public terms, private payload | Permanent | On-chain (`pallet-lease`) | Unchanged |
| Reputation vectors | Consensus | High | Public | Latest value only | On-chain aggregate (`pallet-reputation`), raw evidence off-chain by hash (ADR-011 §3) | Unchanged |
| Payments / Reward Points | Consensus | Highest | Public | Permanent | On-chain (`pallet-rewards`) | Unchanged + streaming settlement (#51) |
| Workload metadata (image ref, resource spec, env) | High | High | **Tenant-private** | Lease lifetime + audit window | PostgreSQL (`control-plane/migrations/000004_workloads.sql`) | Encrypted + replicated; only a commitment hash on-chain |
| Metrics | Attributable | Medium | Semi-private | Bounded window | PostgreSQL + Redis | Replicated + cached. **Never on-chain** — `AGENTS.md:35` bans detailed on-chain metrics and this ADR does not lift that |
| Logs | Attributable | Medium | **Tenant-private** | Bounded, tenant-configurable | Local + PostgreSQL | Encrypted, tenant-scoped, erasable |
| Secrets | Absolute | Tenant-controlled | **Secret** | Until rotated | Off-chain, injected at deploy | Encrypted with tenant-held keys. **Never on-chain, never content-addressed, never in a shared replica in plaintext** |
| Container images | Content hash | High | Public or tenant-private | Long | External registry | Content-addressed; the digest is pinned in the lease so the chain fixes *which* image ran without storing it |
| Dashboard / frontend assets | Reproducible build + signature | High | Public | Versioned, rollback-safe | Served by the Control Plane (`control-plane/internal/dashboard`) | Content-addressed (#35) |
| Audit evidence (challenge payloads, signed responses, timing traces) | Hash-anchored | Medium | Mixed | Long, bounded | Off-chain, referenced by `payload_hash` (ADR-011 §3) | Content-addressed, anchored by the same `payload_hash` |

**Relationship to ADR-008.** ADR-008 remains accepted and remains the operative
rule for Stage 0; it draws the same line at a coarser grain ("provider identity,
offers, leases, validated availability, reputation, and Reward Points on-chain;
users, workload requests, orchestration history, metrics, logs, Docker state, and
secrets off-chain"). This ADR refines that boundary per data class and adds the
target column. Where the two are read together, ADR-008 governs what is
implemented today and this ADR governs what may be built next. Nothing here moves
a class from off-chain to on-chain.

**The one-way rule.** On-chain data cannot be deleted. Therefore no personal
data, no tenant payload, no secret, and no log ever goes on-chain — only hashes
and commitments. This is a privacy constraint, not a storage-cost optimization,
and it is not waivable by a later ADR without a legal review.

### 4. Cross-cutting guarantees

- **Finality.** A fact is authoritative only when it is finalized on-chain, or
  when it is off-chain state that has been reconciled against a finalized chain
  fact. No component may report `RUNNING`, a successful deployment, a settled
  payment, or a reputation change before that — the existing rule at
  `AGENTS.md:19`, restated here because every stage below adds a new component
  tempted to break it.
- **Conflict resolution.** Where multiple writers exist (Stage 1 onward), the
  chain is the tiebreaker: off-chain replicas converge on the ordering implied by
  finalized chain events, never on wall-clock time. Any state a replica holds that
  cannot be tied to a finalized fact is, by definition, a cache.
- **Replay protection.** Generalize the pattern already proven in
  `pallet-availability`: a monotonic per-subject sequence checked with
  `sequence > LastProofSequence::<T>::get(&provider)`
  (`blockchain/pallets/availability/src/lib.rs:350,373`), plus a block-number
  deadline (`Challenge { deadline }`, `blockchain/pallets/availability/src/lib.rs:102`,
  rejected as `ChallengeTimeout` at `:308`). Every new signed message introduced
  by a later stage must carry a subject, a sequence or nonce, and a deadline. No
  new replay scheme is to be invented.
- **Data availability.** Content-addressed data is only as available as the nodes
  pinning it. Any stage that moves a class to content-addressed storage must state
  its pinning and retention strategy and must degrade to an explicit error, never
  to a silent empty result.
- **Erasure and privacy.** Tenant-private classes (workload metadata, logs,
  secrets, private images) must be erasable on request. This is why they are
  encrypted with tenant-held keys rather than merely access-controlled: erasure of
  the key is the erasure mechanism where the ciphertext may already be replicated.
  Public on-chain classes are permanent by design and must contain no personal
  data.
- **Key recovery and rotation.** Every role needs a rotation path that does not
  lose accrued state: a Worker rotating keys must keep its reputation and leases; a
  validator must keep its stake and its unbonding position; a tenant must keep
  access to its encrypted data. Rotation is an on-chain link from old key to new
  key, authorized by the old key, with the same bounded-window and replay rules as
  above. Loss of a key without a prior rotation is not recoverable and must be
  documented as such — no escrow, no backdoor.

### 5. Staged migration

Each stage removes one class of central trust. Stages are ordered by dependency,
not by ambition, and map onto the existing GitHub milestones so the roadmap and
the issue tracker cannot drift apart.

**Stage 0 — today (v0.1 → v1.1).** One Control Plane, PostgreSQL authoritative,
Redis reconstructible, root-gated bridge for registration and leases, Docker
runtime, Control-Plane-configured WireGuard. ADR-008 and ADR-005 hold unchanged.
The only decentralized element is Network Validator scoring (ADR-011). Milestones
v0.2, v0.3, v1.0, v1.1 harden this; they do not decentralize it further.

**Stage 1 — decentralize authority (v3.0).** Remove the single-operator
assumption from state, scheduling, identity, and economics, while the data plane
stays as it is: #33 replicated off-chain data plane, #34 multiple Control Planes
and scheduling relays, #35 content-addressed frontend, #36 decentralized identity
and governance, #50 on-chain orchestration, #51 streaming payments, #52 slashing.

**Stage 2 — decentralize the data plane (v4.0).** Remove the Control Plane from
the packet path: #53 fully P2P WireGuard mesh, #54 gateway nodes for public
ingress, #55 decentralized DNS. Prerequisite: Stage 1's identity work (#36),
because peer authentication cannot rest on a Control-Plane-issued allowlist once
the Control Plane is no longer in the path.

**Stage 3 — decentralize discovery and storage (v5.0).** Remove the Control Plane
from provider discovery and add storage as a first-class verified resource: #56
DHT geo-discovery, #57 Proof of Resource, #58 S3-compatible object storage, #59
replicated block volumes.

**Stage 4 — verifiable and self-healing (v6.0).** Close the operator-collusion
gap left open by §2 and remove human intervention from failure recovery: #60 TEE
support, #61 distributed enclave attestation, #62 auto-healing and migration, #63
infrastructure topology DSL.

Milestone v2.0 (OpenStack compatibility, #22–#27) is an API-surface track. It is
orthogonal to this roadmap and is neither blocked by it nor a prerequisite for
it, provided it introduces no new central authority.

### 6. ADR gates

This ADR authorizes nothing. Each item below needs its own accepted ADR before
implementation, and that ADR is what lifts the specific `AGENTS.md` prohibition
named in the last column.

| Gate | Unblocks | Prohibition it must lift, and what it must settle |
|---|---|---|
| **ADR-013** — replicated off-chain data plane | #33 | "another database". Must settle: event log vs CRDT, deterministic IDs, ordering, snapshots, pruning, and the PostgreSQL deprecation criteria |
| **ADR-014** — multi-Control-Plane and relay protocol | #34 | single-Control-Plane component boundary. Must settle: leader/leaderless rules, idempotency, peer admission, and how an Agent refuses an unauthenticated relay |
| **ADR-015** — slashing and economic penalties | #52 | none (new mechanism). Already demanded by ADR-011 §5, which ships rewards but explicitly defers slashing economics. Must settle: false-positive protection, appeals, and interaction with `dispute_round` |
| **ADR-016** — on-chain orchestration | #50, #62 | "runtime orchestration". Must settle: what scheduling logic is deterministic enough for the runtime, and what stays off-chain |
| **ADR-017** — P2P mesh and DHT discovery | #53, #54, #55, #56 | "direct Agent-to-chain access", and the Control-Plane-mediated key exchange in `control-plane/internal/wireguard/wireguard.go`. Must settle: peer authentication without a central introducer, and what stays lease-gated per ADR-010 |
| **ADR-018** — content-addressed distribution and decentralized storage | #35, #58, #59 | "another database". Must settle: pinning, retention proofs, erasure, and gateway trust |
| **ADR-019** — TEE and distributed attestation | #60, #61 | none (new trust root). Must settle: which vendor roots are trusted, revocation, and what an unattested provider may still do |
| **ADR-020** — decentralized identity, key rotation, and governance | #36 | `EnsureRoot` as governance (`blockchain/runtime/src/lib.rs:316`). Must settle: rotation and recovery per role, stake/delegation, timelocks, and emergency constraints |

Three issues need **no new gate**:

- **#57 Proof of Resource** extends the existing challenge model (ADR-007) and
  evidence-summary model (ADR-011 §3) to CPU/RAM/GPU. It adds no trust boundary.
  It does require a `protocol/proto` change with full consumer analysis per
  `AGENTS.md:19`.
- **#51 streaming payments** is gated on the metering and settlement architecture
  already scoped by #19 (milestone v1.1), not on a new ADR.
- **#63 IaC DSL** needs no gate while it is evaluated off-chain. If any part of it
  is ever evaluated in the runtime, it falls under ADR-016 and inherits the
  determinism, bounded-input, and no-floats rules of `AGENTS.md:23`.

### 7. Trade-offs and rollback

- **Performance.** Every stage trades latency for independence. On-chain
  orchestration (#50) replaces a millisecond database write with a block time;
  DHT discovery (#56) replaces an indexed query with a network walk. Each gate ADR
  must state the latency budget it accepts and what stays off the critical path.
- **Cost.** Replication and content-addressed pinning multiply storage cost by
  the replication factor, and on-chain writes cost fees permanently. Classes stay
  off-chain by default; the burden of proof is on moving something on-chain.
- **Liveness.** Each stage adds a quorum whose bootstrap period has too few
  independent participants. Degraded quorum must be surfaced explicitly — the
  dashboard requirement in #29 is the template for every later stage.
- **Governance.** Stage 1 replaces one sudo key with a governance process. Until
  #36 lands, every gate ADR above is adopted under the current single-key
  authority, which is itself a centralization the roadmap is meant to remove. This
  is accepted and time-bounded, not ignored.
- **Rollback.** Every stage must keep its predecessor operable for one release:
  Stage 1 keeps PostgreSQL authoritative until #33's SLOs are met; Stage 2 keeps
  Control-Plane-configured WireGuard as a fallback path; Stage 3 keeps the
  registry query alongside the DHT; Stage 4's TEE requirement is opt-in per
  workload, never network-wide. A stage that cannot be rolled back has not met its
  exit criteria.

### 8. Explicitly out of scope

This ADR does not specify any mechanism. It does not choose a database, a DHT, a
storage network, a TEE vendor, a governance model, or a token economic policy —
those are the gate ADRs of §6. It does not solve operator-level collusion (§2).
It does not change any code, origin, or storage item today.

## Consequences

- Milestones v3.0 through v6.0 become plannable: every issue now names the ADR it
  waits on instead of being silently blocked by `AGENTS.md`.
- `AGENTS.md`'s prohibition list is reframed from permanent to ADR-gated. The
  rules themselves do not weaken — the security rules, the Protobuf contract
  rules, and the runtime's no-floats/no-unchecked-arithmetic rules are untouched,
  and each prohibition now names the specific gate that may lift it. The frozen
  architecture stays frozen; it simply has documented doors.
- Eight further ADRs are now owed (§6). None of them may be skipped by declaring
  an implementation "small", and each one is a separate change with its own
  consumer analysis.
- The one-way rule in §3 permanently constrains the design: any future proposal to
  put tenant data, logs, or secrets on-chain is out of order without a legal
  review, regardless of how convenient it would be for verification.
- `architecture.md` and `architecture_review.md` §7 contain an older, conflicting
  roadmap numbering (v0.1 PoC / v0.2 Prototype / v0.3 Beta / v1.0 Production).
  `ROADMAP.md` and the GitHub milestones are the source of truth; those two
  documents remain aspirational, as `CLAUDE.md` already warns. Reconciling them is
  separate work.
- The `docs/adr/` directory contains two files numbered `009`
  (`009-control-plane-provider-registration.md` and
  `009-local-aura-grandpa-testnet.md`). This ADR takes `012` and does not renumber
  them; the collision is noted so it is not repeated.
