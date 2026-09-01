# ADR-039: Replicated off-chain data plane

## Status

Accepted (by the repository owner, explicitly, relayed in-session — after reviewing a full summary
of this ADR's decisions and their reasoning, then confirming to proceed with implementation).

Originally written by Claude Code, autonomously, in response to issue #33, held as `Proposed` per
the convention established by ADR-029/036/037/038 until this acceptance. Nothing here is
implemented yet by this ADR itself; issue #33 is unblocked by this acceptance and now carries the
implementation work.

**Numbering note**, following the identical precedent ADR-036/037/038 each already established for
themselves. ADR-012 §6's gate table reserves this design as "ADR-024 — replicated off-chain data
plane," unblocking #33. `039` is the actual next-free ADR number at the time this draft was written
— `git ls-tree` against fresh `origin/main` shows `038` as the highest existing number
(`docs/adr/038-on-chain-workload-orchestration.md`), and `gh pr list --search "docs/adr"` shows no
open PR and no unmerged local/remote branch claiming `039` — not `024`, for the identical reason
every prior gate ADR in this sequence has landed under a different number than its ADR-012
reservation: ADR-012 §6's own "Consequences" policy is *"an unplanned ADR always takes the next
integer... the next accepted ADR of any kind (gate or not) takes the next integer regardless of
what this table says."* This document fulfills the ADR-024 gate's obligation in full: it settles
event log vs. CRDT, deterministic IDs, ordering, snapshots, pruning, and the PostgreSQL-deprecation
criteria, exactly the list ADR-012 §6 names. Every reference below to "the ADR-024 gate" means *this*
document; every reference to "ADR-024" by number, if it ever appears elsewhere, means whatever
ADR-012's table's *reservation* pointed at, not a document that exists.

## Context

Issue #33 asks for a replicated off-chain data plane so no single PostgreSQL instance is required
for critical operational availability, explicitly warning against adding a database casually and
naming seven acceptance criteria (event-log-vs-CRDT justification; deterministic IDs, ordering,
idempotence, conflict resolution, snapshots, pruning, replay; signed state transitions anchored to
finalized chain facts; encrypted private data with explicit key ownership/recovery; reconstructible
caches stay non-authoritative; a named test matrix; measurable SLOs before PostgreSQL deprecation).
It states plainly: *"PostgreSQL remains the MVP authority until this migration is proven."* This ADR
does not flip that rule. It designs the mechanism the rule will eventually be retired against.

### The three-level distinction this ADR must land on level 3 of, stated explicitly before anything else

Established directly with the repository owner before this document was drafted, because it is the
single most important framing decision this ADR makes and the easiest one to get subtly wrong:

1. **Centralized (today).** One PostgreSQL instance, one operator — the Control Plane's own
   database, `AGENTS.md`'s "PostgreSQL is authoritative off-chain," unchanged since ADR-005.
2. **Replicated but still centrally controlled.** Multiple database replicas — a multi-AZ Postgres
   deployment, a read-replica fleet, a Patroni/Citus cluster — all operated by the same single party.
   This improves availability and survives a single node's failure. **It decentralizes nothing**: one
   party still controls every replica, can still silently drop, reorder, or fabricate any record
   across the entire fleet, and no other party can detect it without already trusting that operator.
   A design that stops here does not answer issue #33's actual question — the issue does not ask
   "how do we survive a Postgres failure," it asks how to "replace centralized off-chain state," and
   a same-operator replica fleet is centralized state with better uptime, not decentralized state.
3. **Genuinely decentralized.** Multiple **independently operated** parties each hold a replica of
   the operational history, and no single one of them — including the Control Plane operator itself
   — can unilaterally corrupt, censor, or rewrite that shared history without the others detecting
   it. This is achieved not by a shared consensus cluster (which still requires one party to run and
   trust the cluster's membership) but by making every state transition **signed** (attributable to
   whichever party actually produced it) and **anchored to already-finalized on-chain facts** (which
   are themselves already decentralized, per ADR-011's independently-operated, stake-bonded Network
   Validator set). Verifiability, not consensus-state placement, is what makes this decentralized —
   the exact principle ADR-038 already applied to scheduling decisions (§6 of that document: *"any
   observer with read access to a chain node... can recompute `schedule_workload`'s pure function
   against the same finalized block and get the identical answer... it is one of arbitrarily many
   possible relayers of an already-decided fact"*). This ADR applies the identical reasoning to the
   **operational event history** instead of scheduling decisions: Decision §9 names the concrete
   mechanism.

**This ADR's design lands at level 3, explicitly, with a concrete mechanism (Decision §9), not level
2 dressed up as level 3.** Every design choice below is checked against that bar.

### What is actually true today, read directly from source, not from the architecture docs

**The write pattern is already single-writer-per-subject with explicit total ordering — not a
concurrent multi-writer problem.** `control-plane/internal/workloadapi/postgres.go`, read in full:

- `ClaimNext` (`postgres.go:212-231`) uses `FOR UPDATE SKIP LOCKED` plus a `worker_lease_until`
  fence: exactly one worker process holds the lease to advance a given `workload_id` at any moment,
  and every `Mark*`/`RetryLater`/`AssignLease` write is additionally gated on the exact `version`,
  `worker_id`, and `worker_lease_until` that worker observed when it claimed the row
  (`MarkRunning`'s `WHERE ... version=$3 AND worker_id=$4 AND worker_lease_until>now()`, identical
  shape repeated at every `Mark*` call site). A losing racer gets `ErrConflict`, never a merged or
  reconciled write.
- `AssignLease` (`postgres.go:329-383`) runs inside a `pgx.Serializable` transaction specifically so
  two workers racing to fill the same provider's last slot cannot both observe "capacity still free"
  before either commits — Postgres aborts the loser outright (`isSerializationFailure`), which the
  caller surfaces as a retry, never a merge of two partial capacity commitments.
- A workload runs on exactly one provider at a time by construction (ADR-012 §2's own vocabulary:
  "Worker/Provider... an operator running a Provider Agent"), so `metering_evidence`'s per-
  `(provider_id, workload_id)` monotonic `sequence` (`migrations/000016_metering_evidence_and_
  invoices.sql:31-37`, gated by `metering_cursors`'s row lock before any `sequence > last_sequence`
  check) is produced by exactly one signer for that pair, never two independent Agents racing to
  report the same workload's usage.
- On-chain, `pallet-lease::Lease.state` (`blockchain/pallets/lease/src/lib.rs:51-70`) is a strict
  transition table (`Created → Active → {Completed, Expired, Disputed}`, `Disputed → Completed`)
  enforced by `update_lease_state`'s own `ensure!(matches!(...))` — chain-ordered by construction,
  no concurrent-writer ambiguity possible once a block finalizes.

**This is the load-bearing fact Decision §1 builds the event-log-vs-CRDT choice on.** Every write
this system does today is already serialized to one legitimate next value per subject — by an
explicit fencing token (Postgres), a monotonic sequence (metering evidence), or block finality
(chain state). Nothing in this codebase's actual write pattern needs *merging* two independently
authored, concurrent updates to the same subject; it needs *rejecting* everything but the one
legitimate next step.

**This codebase already has one instance of exactly the pattern this ADR generalizes.**
`metering_evidence` (ADR-029 §6, `migrations/000016_metering_evidence_and_invoices.sql`) is already
an append-only (§header comment: *"nothing in `internal/metering` ever UPDATEs or DELETEs a row
here"*), per-subject-sequenced (`UNIQUE(provider_id, workload_id, sequence)`), Ed25519-signed
(`internal/metering/signing.go`'s domain-separated `signedBytes`, `openinfra-metering-v1\x00`) event
log, with its own append-only rejection trail (`metering_evidence_rejections`, for anything that
fails signature/sequence/bound checks) sitting alongside it rather than silently dropping bad input.
This ADR does not invent a new pattern; it generalizes an already-shipped one from a single subject
class (metering) to the workload-lifecycle and lease-correlation classes issue #33 actually asks
about, and it reuses `internal/metering/signing.go`'s own reasoning for why the signed bytes are a
hand-rolled canonical encoding, not a proto marshal (*"agreement never depends on prost and
protobuf-go producing byte-identical output"*) — the identical concern applies to every event class
below, not just metering.

**The Control Plane's own signing key already exists and is already Ed25519.**
`control-plane/internal/blockchainbridge/registrar.go:382-387`: `"Substrate signer key must use
Ed25519"`, `registrar.account` derived from `privateKey.Public().(ed25519.PublicKey)`. This is the
same key type `agent-core::identity::Ed25519IdentityManager` already uses for every provider, and
the same key type `pallet-provider-registry::Provider.public_key` already stores on-chain. The whole
network already standardizes on Ed25519 for every signer that exists today — this ADR's design reuses
that, introducing no new key type or enrollment ceremony (Decision §3).

**`EventEnvelope` already exists in the wire protocol, unused.** `protocol/proto/openinfra/shared/
v1/shared.proto:171-178` defines `EventEnvelope { event_id, event_type, timestamp, source, payload,
signature }` — and `grep -rl EventEnvelope control-plane --include=*.go` finds **zero** real
consumers. It is a reserved, dormant message with no subject/sequence/anchor fields and no
implementation anywhere. Decision §3 proposes evolving it, not replacing it with a parallel type.

**The actual tenant-private surface is smaller than ADR-012 §3's table implies, read honestly.**
`WorkloadDefinition` (`shared.proto:107-113`) carries `workload_id`, `profile`, `requirements`,
`constraints`, `duration_seconds` — no env vars, no secrets field, nothing resembling injected
credentials anywhere in `agent.proto` or `shared.proto` today (grepped explicitly, confirmed empty).
`worker.go`'s `SCHEDULING` case already calls `decodeDefinition(item.Definition)` — the Control
Plane already fully decodes and reads `WorkloadDefinition` in-process today; it is not currently
treated as opaque, encrypted, or end-to-end-protected from the Control Plane's own view. This ADR is
honest about that starting point (Decision §7) rather than implying an encryption boundary already
exists where it does not.

**Reconstructible caches, confirmed unaffected by this ADR's scope.**
`control-plane/internal/agentmanager/directory.go`'s `RedisLivenessStore` (`HeartbeatPayload`,
`heartbeatKeyPrefix`) holds only a TTL'd heartbeat payload per provider, rebuilt every ~15s from the
Agent's own live report — nothing here is a candidate for replication or authority, and nothing in
this ADR proposes changing that. `control-plane/internal/wireguard/wireguard.go`'s `Manager` holds
in-memory WireGuard peer state (`m.peers`), explicitly reconstructed from an authoritative lease on
`Attach` and torn down on `Revoke`/lease completion — also out of scope, also confirmed unchanged.

### The existing on-chain facts this ADR anchors against — no new on-chain state proposed

`pallet-lease::create_lease` (`blockchain/pallets/lease/src/lib.rs:120-162`) already emits
`Event::LeaseCreated { lease_id, provider, consumer, end }` and `update_lease_state` already emits
`Event::LeaseStateChanged { lease_id, old_state, new_state }` — both real, already-shipped, already
finalized-and-queryable chain facts. ADR-038 (accepted, not yet implemented) adds
`pallet-scheduling::ScheduledWorkloads: StorageMap<[u8; 32] workload_id_hash, LeaseId>`, an even
earlier anchor point once it ships. `pallet-provider-registry::Provider.public_key`
(`blockchain/pallets/provider-registry/src/lib.rs`) is the existing, already-finalized source of
truth for verifying a provider-signed event's signer. **This ADR proposes no new pallet, no new
runtime storage, and no new extrinsic** — Decision §5 anchors exclusively against state that already
exists, which is the minimal, already-justified answer to "does this need genuinely new on-chain
state" (it does not).

## Decision

### 1. Event log, not CRDT — reasoned from this codebase's actual write pattern, not picked by default

**Rejected: CRDTs.** A CRDT earns its complexity when independent, possibly-disconnected writers
must be able to mutate the *same logical object concurrently* and merge divergent results later
without coordination — the canonical cases are collaborative editing, distributed counters, or
membership sets where refusing a write until a coordinator is reachable is unacceptable. Nothing in
this codebase's actual write pattern (Context, above) has that shape: `ClaimNext`'s row-lock fencing,
`AssignLease`'s Serializable-transaction rejection of a losing racer, `metering_evidence`'s
per-`(provider,workload)`-single-signer sequence, and `pallet-lease`'s own strict transition table
all already **reject** a second concurrent write to the same subject rather than needing to **merge**
it. Issue #34 (multi-Control-Plane, the adjacent, still-gated concern) asks for exactly the same
posture at the write-coordination layer: *"no duplicate leases, deployments, stops, rewards, or
reservations under concurrent replicas... deterministic idempotency, leader/failover or leaderless
rules"* — that is a request for coordinated, deterministic single-decision-per-subject semantics,
the opposite of CRDT's automatic-merge model. Concretely, a `workloads` row's fields are
cross-field-invariant-heavy (`migrations/000004_workloads.sql`'s own `CHECK`s: no `RUNNING` without
`container_id`, no `LEASED`/`DEPLOYING`/`RUNNING` without `lease_id`) — a CRDT merge function safe
enough to never produce an invalid combination of those fields under concurrent divergent updates
would have to re-derive the entire state machine by hand, per field, which is strictly more design
and audit surface than "reject anything that isn't the next legitimate step," not less.

**Chosen: a signed, per-subject, hash-chained, append-only event log** — the exact shape
`metering_evidence` already established for one subject class, generalized. Concretely:

```
EventLogEntry {
    subject_type:      enum   // WorkloadLifecycle | LeaseCorrelation | MeteringEvidence | ...
    subject_id:        bytes  // workload_id, or (provider_id, workload_id) for metering
    sequence:          u64    // monotonic per (subject_type, subject_id), starts at 1
    prev_event_hash:   [u8; 32]  // hash of the previous event for this subject; zero for sequence=1
    event_type:        string    // e.g. "SCHEDULING", "LEASED", "RUNNING", "FAILED"
    payload:           bytes     // plaintext for operational metadata; ciphertext for tenant-private data (§7)
    payload_hash:      [u8; 32]
    chain_anchor:      Option<ChainAnchor>   // §5 — absent only when genuinely no chain fact exists yet
    signer_public_key: [u8; 32]  // Ed25519, resolved on-chain (provider) or the CP's own bridge key (§3)
    signature:         [u8; 64]  // Ed25519 over the canonical byte encoding below, not a proto marshal
    recorded_at:       Timestamp // informational only — never the ordering key (ADR-012 §4)
}
ChainAnchor { lease_id: u64, block_hash: [u8; 32] }
```

`event_id` (the acceptance criterion's "deterministic event ID") is **not** a random UUID — it is
`sha256("openinfra-eventlog-v1\x00" || subject_type || be_u32(len(subject_id)) || subject_id ||
be_u64(sequence) || prev_event_hash || event_type || payload_hash)`, the same domain-separated,
hand-rolled canonical encoding `internal/metering/signing.go`'s `signedBytes` already establishes
for exactly this reason (byte-identical across Go and Rust regardless of each language's proto
marshal implementation). Two independently-constructed replicas that received the same event
compute the same `event_id` without coordinating — the definition of deterministic.

This directly answers the "is this CRDT-friendly, or does the write pattern argue for something
simpler" instruction: it argues for something simpler, and the simpler thing is what this codebase
already partially built.

### 2. Ordering: per-subject monotonic sequence, hash-chained — no new replay scheme invented

Per ADR-012 §4's explicit instruction: *"Generalize the pattern already proven in
`pallet-availability`: a monotonic per-subject sequence checked with `sequence >
LastProofSequence::<T>::get(&provider)`... Every new signed message introduced by a later stage must
carry a subject, a sequence or nonce, and a deadline. No new replay scheme is to be invented."* This
ADR follows that instruction literally: `sequence` is `LastProofSequence`/`metering_cursors.
last_sequence`'s exact shape, generalized from "per provider" / "per (provider, workload)" to "per
`(subject_type, subject_id)`" — no vector clocks, no Lamport timestamps, no hybrid logical clocks.
Global cross-subject ordering is not needed and is not attempted: each subject's log is
independently, per-subject totally ordered (matching the single-writer-per-subject write pattern
§1 establishes), and cross-subject causality (e.g. "this workload's `LEASE_PENDING` event happened
after this lease's `LeaseCreated` on-chain fact") is expressed through `chain_anchor` referencing a
block the chain itself already totally orders — reusing the chain as the cross-subject clock, the
literal text of ADR-012 §4's "Conflict resolution" rule: *"the chain is the tiebreaker: off-chain
replicas converge on the ordering implied by finalized chain events, never on wall-clock time."*
`recorded_at` exists for human/operator legibility only and participates in no ordering decision
anywhere in this design.

`prev_event_hash` hash-chains each subject's own sequence (the same idea Certificate Transparency
logs and `git`'s own commit history use, scoped per-subject rather than globally so verifying one
workload's history never requires downloading the whole network's log — mirroring
`metering_evidence_workload_idx`'s existing per-workload scoping). A replica holding a gap-free,
hash-chain-verified run of events for a subject has cryptographic assurance it has that subject's
*complete*, unmodified history, not merely a valid-looking but truncated or reordered subset — this
is what makes tampering **detectable**, not just replication technically correct.

### 3. Who signs what — reusing existing keys, no new enrollment

- **Provider-attested facts** (deployment confirmation from the Agent's own perspective, metering
  evidence — already shipped per ADR-029 §6, heartbeat-derived liveness) are signed by the Provider
  Agent's existing `agent-core::identity::Ed25519IdentityManager` key, verified against
  `pallet-provider-registry::Provider.public_key`, exactly `internal/metering/signing.go`'s
  `verifySignature` already does for one event class. No new keypair, no new enrollment step.
- **Control-Plane-originated facts** (the state transitions the Control Plane itself decides —
  `SCHEDULING`'s outcome pre-ADR-038, dispatch attempts, `AssignLease`'s capacity decision) are
  signed by the Control Plane's **existing** bridge-account Ed25519 key (`blockchainbridge/
  registrar.go`), the same key already trusted to sign every on-chain extrinsic this system submits.
  Reusing it here is the smallest possible addition — no new key infrastructure, no new trust
  ceremony, and it means an event's signer is checkable against a key whose public half is *already*
  published (on-chain, at `pallet-provider-registry` registration time in the provider case; via the
  bridge account's already-known `Account()` in the Control Plane case).
- **Tenant-attested facts**, once ADR-029 §3/§12's tenant-held on-chain key work lands (named there
  as required, non-optional future work, still absent today), would sign workload-submission events
  directly. Until then, a `WorkloadLifecycle` subject's `sequence=1` event is Control-Plane-signed
  only — named honestly as a gap in §9, not glossed over.

### 4. Idempotence and conflict resolution

**Idempotence**: `(subject_type, subject_id, sequence)` is a hard uniqueness constraint, mirroring
`metering_evidence`'s own `UNIQUE(provider_id, workload_id, sequence)` and ADR-038 §2's
`ScheduledWorkloads` idempotency-key precedent. A duplicate append for an already-occupied
`(subject_id, sequence)` is rejected outright (not silently merged, not silently ignored) — the
appending party must observe the actual current sequence and retry at the correct next value, the
same "no top-up, no silent re-charge" discipline `pallet-escrow::complete_and_payout` already
established for a different kind of duplicate-submission risk (ADR-029 §6).

**Conflict resolution**: because every subject has exactly one legitimate signer-at-a-time by
construction (§1), a "conflict" in this design is never two valid updates that must be merged — it
is always one of: (a) a duplicate/stale sequence (rejected, above); (b) a signature that fails to
verify against the claimed signer's known public key (rejected, quarantined — §6); (c) a
`chain_anchor` that does not correspond to a real, finalized on-chain fact (rejected, quarantined —
§5/§6); or (d) a hash-chain break (`prev_event_hash` does not match the actual previous event's
`event_id`) — evidence of a corrupted, reordered, or tampered replica, surfaced as a hard
verification failure a witness must report, never silently repaired. There is no case in this
design where two divergent-but-individually-valid events for the same `(subject_id, sequence)` both
exist and must be reconciled by a merge function — the sequence uniqueness constraint makes that
structurally impossible by construction, not merely unlikely.

### 5. Anchoring to finalized chain facts — concrete, per event class, honest about the gap

**Concretely, for a workload's lifecycle events once a lease exists**: from `LEASE_PENDING` onward,
every event for that `workload_id` carries `chain_anchor = { lease_id, block_hash }`, where
`block_hash` is the finalized block at which the Control Plane observed the relevant
`pallet-lease::LeaseCreated`/`LeaseStateChanged` event (or, once ADR-038 ships,
`pallet-scheduling::ScheduledWorkloads[workload_id_hash]`). An independent verifier holding only (a)
a replica of the event log and (b) read access to any chain node — not necessarily the Control
Plane's own node — can check: does `lease_id` actually exist on-chain at `block_hash`, for this
`provider`/`consumer`? Is the lease's on-chain `state` consistent with what this off-chain event
claims (e.g. an off-chain `RUNNING` event should never precede an on-chain lease that is still
`Created`, never `Active`)? This is the identical mechanism ADR-038 §6.2 already introduced one field
for (`DeployRequest.scheduling_block_hash`, "purely for audit correlation... upgrades what an
external auditor can do from 'trust the dashboard' to 'independently re-run the same deterministic
check against this exact block'") — this ADR generalizes that one field to every lifecycle event
once a lease exists, rather than inventing a parallel mechanism.

**Honestly, what cannot be anchored: the `REQUESTED`/pre-lease events.** A workload's very first
event (`sequence=1`, before `AssignLease` has produced a real `lease_id`) has no on-chain fact to
reference yet — there is nothing to check it against. This is not solved by this ADR, and is named
explicitly rather than silently assumed away, the same discipline ADR-038 §1 used for liveness (*"a
real, accepted gap, not solved here"*): a pre-lease event is verifiable only as "signed by a known
key" and "correctly hash-chained" (so it cannot be retroactively inserted or reordered without
breaking that subject's chain), never as "consistent with an independent chain fact," because no
such fact exists at that point in a workload's life. Once `AssignLease` produces a `lease_id`, every
subsequent event closes that gap for everything downstream.

**Metering evidence already has its own anchor** — `lease_id`, per ADR-029 §6 — and needs no change;
this ADR's `chain_anchor` shape is a superset of what `metering_evidence` already implicitly carries.

### 6. Replay, verification, and quarantine — reconstructible caches stay reconstructible, one level up

A new or recovering replica reconstructs its local projection by reading a subject's event log from
genesis (or the latest verified snapshot, §7) forward, verifying at each step: the hash chain
(`prev_event_hash` matches), the signature (against the claimed signer's known public key), and —
where present — the chain anchor (§5). An event failing any check is **quarantined**, not silently
dropped and not silently accepted: a new, append-only `event_log_rejections` table, the direct,
generalized analog of `metering_evidence_rejections` (*"an append-only audit trail of every
submission... never joined into anything billing-relevant"*), recording what failed and why, so a
corrupted or malicious upstream is inspectable evidence, not an invisible gap.

This directly satisfies issue #33's "reconstructible caches remain non-authoritative" criterion by
generalizing, not weakening, the existing rule. Today: Redis is reconstructible from PostgreSQL
(authoritative) plus live heartbeats. Under this design: PostgreSQL's row-shaped tables
(`workloads`, and any future lease-correlation table) become **projections**, reconstructible by
replaying the signed, verified event log — which becomes authoritative — while Redis's role is
completely unchanged, reconstructible from Postgres/live state exactly as today. One authority tier
moves up; the derived-cache discipline that already governs Redis is preserved unchanged, not
invented anew.

### 7. Encrypted tenant-private data — the mechanism this ADR must provide, honestly scoped against what exists today

ADR-012 §3's target placement for "Workload metadata" is *"Encrypted + replicated; only a commitment
hash on-chain"* and issue #33 requires *"encrypted private workload/user data with explicit key
ownership and recovery."* Read honestly against Context, above: **today's actual wire protocol
carries no secrets or env-var field anywhere**, and the Control Plane already fully decodes
`WorkloadDefinition` in-process at scheduling time (`worker.go`'s `decodeDefinition` call in the
`SCHEDULING` case) — there is no existing end-to-end encryption boundary between tenant and Agent to
preserve, because none exists today. This ADR does not claim to close that gap for the CP's own
scheduling-time access (a materially larger change — CPU/RAM/storage/zone fields must remain
CP-readable in plaintext for scheduling to function at all, on-chain or off, per ADR-038 §1's own
finding that the runtime, too, needs these fields readable). What this ADR **does** provide is the
general envelope-encryption mechanism ADR-012 §3 requires for whichever fields are genuinely
tenant-private, applied wherever such a field exists now or is added later (a near-future
secrets-injection feature will need this immediately):

- Each tenant-private payload is encrypted client-side (before it ever reaches the Control Plane, in
  the dashboard or CLI that constructs the submission) under a fresh, per-event symmetric Data
  Encryption Key (DEK).
- The DEK is wrapped (asymmetric envelope encryption, e.g. X25519) under the tenant's own held
  public key — never under any Control-Plane- or provider-held key.
- The event log's `payload` field for such an event carries only: the ciphertext, the wrapped-DEK
  blob, and `payload_hash` (a commitment hash of the plaintext) — never plaintext. This is exactly
  ADR-012 §3's "only a commitment hash... may cross that line" language, applied to the replicated
  log instead of on-chain state, where the identical one-way-erasure reasoning applies: on-chain data
  cannot be deleted (ADR-012 §3's "one-way rule"), and a replicated, witness-held log has the same
  property in practice — anything ever written to it should be assumed permanently retrievable by
  *someone*, so plaintext tenant-private data must never be written to it at all, only ciphertext
  plus a commitment.
- **Erasure** = destroying the tenant's key (or the specific wrapped-DEK blob), the exact mechanism
  ADR-012 §4 already prescribes for every tenant-private class (*"erasure of the key is the erasure
  mechanism where the ciphertext may already be replicated"*) — not deleting the ciphertext itself,
  which may be infeasible once witnesses hold their own copies.
- **Key ownership and recovery are explicitly not solved by this ADR.** Tenants have no on-chain
  identity today (ADR-012 §2's vocabulary table, reconfirmed unchanged by ADR-029 §3/§12), and no
  key-custody or recovery mechanism exists for a tenant-held asymmetric key anywhere in this
  codebase. This ADR specifies the *mechanism* (envelope encryption, DEK-per-event, ciphertext+hash
  in the log) that any current or future tenant-private field must use; it does **not** design key
  generation, storage, backup, or recovery for tenants — that is real, separate, load-bearing work
  named explicitly in Open Questions, not assumed solved by naming the mechanism that depends on it.

### 8. Snapshots and pruning

**Snapshots**: every `SnapshotInterval` events (a tunable, not fixed here) per `(subject_type,
subject_id)`, or whenever a subject reaches a terminal state (`RUNNING`'s final settling,
`COMPLETED`, `FAILED`, `STOPPED`), a signed **snapshot event** is appended — `event_type =
"SNAPSHOT"`, `payload` = the subject's full current projected state, signed by whichever party is
canonical for that subject at that point (the Control Plane for `WorkloadLifecycle`, per §3). A late
or recovering replica joining after genesis need only replay from the most recent verified snapshot
forward, not from `sequence = 1` — bounding catch-up cost regardless of how long a subject's history
has grown, the same "log compaction" idea event-sourced systems generally use, scoped per-subject to
match this design's existing per-subject verification boundary (§2).

**Pruning**: raw events for a subject may be pruned once superseded by a verified snapshot and past
a `RetentionWindow` (a governed, operator-set constant, not fixed here) — but **never** for a subject
whose terminal snapshot has not yet been independently verified by at least one witness beyond the
Control Plane itself, closing off "prune, then claim the pruned history said whatever is convenient"
as an attack a single centrally-controlled pruning schedule would otherwise enable. `event_log_
rejections` (§6) is never pruned on the same schedule — it is the audit trail of *disagreement*, and
pruning it defeats its purpose.

### 9. Who are the independent operators, concretely — and why this ADR does not wait on ADR-017/#34

**This ADR stands alone, decoupled from ADR-012 §6's ADR-017 gate (#34, multi-Control-Plane).**
Stated explicitly, per the task's own instruction to pick one and justify it:

#34 asks for **write-path** decentralization — multiple Control Planes that can each originate new
state, with leader/leaderless coordination, peer admission, and "no duplicate leases/deployments...
under concurrent replicas." That is a strictly harder, separable problem this ADR does not attempt
to solve, and accepting this ADR does not require it to be solved first. What this ADR provides
instead, and what actually answers issue #33's "replicated data plane, no single PostgreSQL instance
required for critical operational availability" without waiting for #34, is the exact move ADR-038
already made for scheduling: **decouple who may verify and replicate a fact from who currently
originates it.**

Concretely: any independent party — a tenant, a third-party auditor, a future second Control Plane
once #34 exists, a public block-explorer-style watchdog — can run a **witness**: a process that
subscribes to the signed event stream (§10), independently verifies every event's hash chain,
signature, and chain anchor (§6), and keeps its own append-only copy. A witness requires no special
relationship with the Control Plane beyond read access to the stream and read access to a chain
node — it does not need to be, or coordinate with, a second Control Plane in #34's sense at all.

This is where the three-level framing (Context, above) resolves concretely, **per event class, named
honestly rather than claimed uniformly**:

- **Provider-attested events** (metering evidence, deployment confirmations) are, today, already
  authored by genuinely independent parties — every registered provider is by definition an
  independent operator (ADR-012 §2's own vocabulary). For this class, level 3 is real *today*: no
  single provider, and no Control Plane relaying a provider's signed evidence, can forge what that
  provider did not sign.
- **Control-Plane-originated events** (the decisions the CP itself makes — pre-ADR-038 scheduling
  outcomes, dispatch attempts) are, today, authored by exactly one key (§3) — **authorship** of this
  class stays centralized until #34 lands, named honestly, not obscured. What this ADR achieves for
  this class *now*, without #34, is **detection, not prevention of the authorship monopoly**: any
  witness holding a verified replica can catch the Control Plane silently reordering, backdating, or
  omitting one of its own events (a hash-chain break, a signature over a fabricated `chain_anchor`
  that does not match what the chain actually finalized, or a gap in an otherwise-sequential replica
  another witness independently holds), and can make that divergence a public, falsifiable,
  reproducible claim — exactly ADR-038 §6's own framing, applied here: *"a divergence... becomes a
  falsifiable, reproducible claim anyone can check, not an assertion resting on the operator's
  word."* This is real, if narrower than full write-path decentralization: it does not stop a
  compromised Control Plane from attempting to censor or fabricate an event, only guarantees the
  attempt is independently detectable by anyone running a witness, the identical "not prevented in
  real time... detected after the fact" honesty ADR-038's own threat model already accepted for its
  own analogous gap (ADR-038 Threat model, first bullet).

**When #34/ADR-017 eventually lands**, a second Control Plane replica becomes, structurally, a
second *event-log writer* — one that must itself follow this ADR's signing, sequencing, and
anchoring discipline, plus whatever leader/idempotency rules ADR-017 layers on top for reconciling
two simultaneous writers. This ADR's mechanism is therefore forward-compatible with #34 without
requiring it: #34 is a natural future *consumer* of the witness protocol this ADR defines, not a
prerequisite for it.

### 10. Storage and replication mechanism — an additive table and an export protocol, not "another database"

Directly answering issue #33's own warning ("do not add a database casually") and `AGENTS.md`'s
gated prohibition this ADR is the accepted door for ("another database, ADR-024, ADR-021"): **this
ADR does not add a new database engine.** The authoritative event log is a new, additive PostgreSQL
table, `event_log`, on the same (today, single) Control Plane instance that already runs Postgres —
insert-only, `UPDATE`/`DELETE` never issued against it, the identical operational shape
`metering_evidence` already has in production today. No CockroachDB, no etcd, no second Postgres
cluster, no new storage engine of any kind is introduced.

What is genuinely new is the **verifiability/export layer**: a streaming export RPC (a new
`protocol/proto` surface, most naturally an evolution of the already-reserved-but-unused
`EventEnvelope` message — extended with `subject_type`/`subject_id`/`sequence`/`prev_event_hash`/
`chain_anchor` fields — rather than a parallel message type; a genuine proto change requiring its own
full consumer analysis at implementation time, per `AGENTS.md`, not attempted here) that any
independently-run witness process can subscribe to (`SubscribeEvents(subject_type, since_sequence)
returns (stream EventLogEntry)`, conceptually) and pull a verified copy from. **A cluster of
mutually-trusting database replicas would not answer level 3 at all** (Context, above) — it would
still be one operator's infrastructure end to end. The witness protocol is the mechanism that
actually lets independent parties hold independently-useful copies, and it is protocol/export
surface, not a second storage engine — the smaller, better-justified addition this gate exists to
permit.

### 11. Rollout: additive dual-write, not a replacement, matching ADR-038's own rollback discipline

Per ADR-012 §7 ("every stage must keep its predecessor operable for one release") and issue #33's
own text ("PostgreSQL remains the MVP authority until this migration is proven"): this ADR's
implementation is **additive**, not a cutover. Every existing `workloadapi.PersistentStore` write
call site (`BeginScheduling`, `AssignLease`, `MarkLeased`, `MarkDeploying`, `MarkRunning`,
`MarkStopped`, `MarkFailed`, `RetryLater`) keeps writing `workloads` rows exactly as it does today,
**and, in the same Postgres transaction** (no distributed-transaction problem — both tables live in
the same database instance for now), appends one corresponding signed `event_log` row. `workloads`
does not become a read-only projection under this ADR; it stays the live, directly-written table it
is today, dual-written alongside the new log. A governed toggle (matching `EscrowPaused`'s and
`OnChainSchedulingEnabled`'s established shape) disables event-log export to witnesses without
affecting `workloads`-table operation at all, so this feature can be operated, monitored, and rolled
back independently of core workload-lifecycle correctness. **Flipping `workloads` to a purely
replay-derived projection, and any actual PostgreSQL deprecation, is explicitly out of scope for this
ADR** — that is a future ADR's decision, gated on the SLOs below being met, not a decision this
document makes for it.

### 12. PostgreSQL-deprecation SLOs — measurable, not yet met, not decided here

Issue #33's own acceptance criterion: *"measurable consistency and availability SLOs before
PostgreSQL deprecation."* This ADR proposes the criteria, does not claim they are met, and does not
itself deprecate anything:

- **Replay fidelity**: every independently-run witness, replaying the same verified log prefix,
  produces a byte-identical projected state (a state-hash comparison, run periodically across every
  live witness) — zero undetected divergence for a full release cycle.
- **Witness diversity and uptime**: at least three genuinely independently-operated witnesses (not
  three processes run by the same party) continuously online for one full release cycle, matching
  ADR-012 §7's "keep predecessor operable for one release" bake-in convention.
- **Latency budget, stated honestly, not assumed free**: p99 event-append-plus-witness-ack latency
  must not regress the existing workload-lifecycle step latency beyond an explicit, stated ceiling —
  per ADR-012 §7's instruction that "each gate ADR must state the latency budget it accepts."
- **Recovery, corruption, and partition tests, passing, not merely designed** — see Tests required,
  below, mapping directly to issue #33's own named scenarios (mixed-version migration, partition,
  node loss, catch-up, corruption, rollback).
- **Erasure verified**: a tenant-initiated key-destruction erasure request (§7) confirmed to render
  the corresponding ciphertext unrecoverable across every live witness within a bounded window.

Until every criterion above is met and independently confirmed, `AGENTS.md`'s "PostgreSQL is
authoritative off-chain" rule stays exactly as it is — this ADR does not weaken it, and does not set
a date.

## Threat model

Enumerated concretely, per this codebase's established convention (ADR-029 §9, ADR-036 §7, ADR-038
Threat model), not gestured at:

- **A compromised or malicious Control Plane silently drops, reorders, or backdates one of its own
  events.** Not prevented in real time — detected after the fact by any witness noticing a hash-chain
  break, a sequence gap, or a `chain_anchor` inconsistent with independently-observed finalized chain
  state (§9). The primary residual risk this ADR carries forward, stated as such, matching ADR-038's
  identical honesty about its own analogous gap.
- **A Control Plane fabricates an entirely new, plausible-looking event for a subject it controls.**
  Closed for any event claiming a `chain_anchor`, once one exists (§5): the claimed `lease_id`/state
  must actually be finalized on-chain, independently checkable by any witness with chain read access.
  **Not closed** for pre-lease events (§5's honestly-named gap) — a fabricated `REQUESTED` event is
  detectable only if it breaks that subject's hash chain (e.g. a later, legitimately-sequenced event
  from a different party doesn't fit), not independently verifiable against a chain fact, because none
  exists at that point.
- **Replay of a stale event.** Closed by the `(subject_type, subject_id, sequence)` uniqueness
  constraint (§4) — a duplicate append is rejected outright, never merged or silently accepted.
- **A malicious or buggy witness reports a false divergence to discredit a legitimate Control
  Plane.** Not specially mitigated by this design — a witness's claim of divergence is only as
  credible as the cryptographic evidence (hash chain, signatures, chain anchors) it can produce
  alongside it; a bare accusation with no verifiable evidence carries no more weight than any other
  unsubstantiated claim. Named as a real, if bounded, griefing surface this ADR does not solve.
- **Tenant key loss.** Named explicitly, not solved: per ADR-012 §4's existing rule ("loss of a key
  without a prior rotation is not recoverable... no escrow, no backdoor"), a tenant who loses their
  encryption key (§7) permanently loses access to any tenant-private payload encrypted under it. This
  ADR does not add key escrow, and ADR-012 §4 already forbids one.
- **Witness collusion / Sybil witnesses.** Out of scope, inherited unchanged from ADR-012 §2's
  already-accepted gap (*"Distinct `AccountId`s controlled by one human are indistinguishable
  on-chain"*) — a set of witnesses secretly controlled by the same operator as the Control Plane
  itself provides no real independent verification, and nothing in this design can distinguish that
  from genuine independence, the same limitation every other ADR in this roadmap already names for
  itself rather than claiming to solve.
- **Event-log growth / unbounded storage.** Mitigated structurally by snapshots and governed pruning
  (§8), bounded the same way `MaxMeteringPeriodSeconds`/`RetentionWindow`-shaped constants already
  bound other unbounded-growth risks in this codebase (ADR-029 §7).
- **Corruption of the authoritative `event_log` table itself** (disk corruption, an operational
  mistake, a bug in the append path). Detected by any witness whose independently-held copy diverges
  from what the Control Plane now serves — the same detection mechanism as deliberate tampering,
  which is the point: this design does not need to distinguish malice from an honest operational
  failure to catch either.

## Tests required (mapping directly to issue #33's named scenarios)

1. **Mixed-version migration.** A witness running an older schema/protocol version can still verify
   and replay events written by a newer Control Plane, or fails closed with an explicit, actionable
   error — never a silent misinterpretation, matching `metering_schema_version`'s existing "explicit
   version, no silent reinterpretation" convention (ADR-029 §1).
2. **Partition.** A witness disconnected from the export stream mid-replay resumes correctly from its
   last verified `sequence` per subject once reconnected, with no gap and no duplicate acceptance.
3. **Node loss.** The Control Plane's own `event_log` table survives a crash-and-restart with no
   torn writes (the same transactional guarantee `workloads` already has today, since both tables
   share one transaction per §11) and no witness-visible corruption.
4. **Catch-up.** A brand-new witness joining after a subject has accumulated a long history replays
   correctly from the most recent verified snapshot (§8), not from genesis, within a bounded time.
5. **Corruption.** A deliberately corrupted event (bad signature, broken hash chain, a `chain_anchor`
   referencing a lease that does not exist on-chain) is quarantined into `event_log_rejections` (§6),
   never accepted into any witness's authoritative projection, and never silently dropped without a
   record.
6. **Rollback.** With event-log export disabled via the governed toggle (§11), `workloads`-table
   operation (the entire existing workload lifecycle, unmodified) continues exactly as it does today,
   verified by the entire existing worker.go test suite passing unmodified.

Plus, not named in the issue but required by this ADR's own design: a cross-witness state-hash
comparison test (replay fidelity, §12) and an erasure test (§7/§12: destroying a tenant's key
renders the corresponding ciphertext unrecoverable, verified across multiple witnesses independently).

## Out of scope

- Any change to `pallet-lease`, `pallet-provider-registry`, or any other pallet — this ADR anchors
  against existing on-chain facts and proposes no new on-chain state (Context, "existing on-chain
  facts" section).
- Multi-Control-Plane write coordination (leader/leaderless rules, peer admission, relay
  authentication) — ADR-017's gate, #34, explicitly decoupled (§9).
- Direct Agent-to-chain access of any kind — ADR-020's gate, untouched by this design; every
  chain-anchor check in this ADR is performed by a witness or the Control Plane, never the Agent.
- Flipping `workloads` from a directly-written table to a purely replay-derived projection, and any
  actual PostgreSQL deprecation — gated on §12's SLOs, a future ADR's decision (§11).
- Tenant key generation, custody, backup, and recovery infrastructure — the encryption *mechanism*
  is specified (§7), the key-management system it depends on is not designed here, named explicitly
  as required future work.
- On-chain checkpoint commitment of the event log's Merkle/hash-chain state (a strengthening
  mechanism briefly considered, not designed) — raised in Open Questions, not decided here.
- A fee, incentive, or reward mechanism for running a witness — nothing in this ADR requires payment
  to operate one, and no such mechanism is proposed.
- Any change to `internal/metering`'s existing, already-shipped evidence pipeline — this ADR builds
  on its pattern, does not modify it.

## Consequences

- A new, additive PostgreSQL table, `event_log` (insert-only, no `UPDATE`/`DELETE`, mirroring
  `metering_evidence`'s existing operational shape), plus its append-only rejection trail,
  `event_log_rejections` (mirroring `metering_evidence_rejections`) — no new database engine.
- A new `protocol/proto` surface: an evolved `EventEnvelope` message (new fields:
  `subject_type`/`subject_id`/`sequence`/`prev_event_hash`/`chain_anchor`) and a new streaming
  export RPC — both requiring full consumer analysis at implementation time, per `AGENTS.md`, not
  attempted here.
- Every `workloadapi.PersistentStore` write call site in `internal/orchestrator/worker.go` and
  `internal/workloadapi/postgres.go` gains one additional, same-transaction `event_log` append per
  state transition — `workloads` itself is otherwise unmodified.
- A new, required, non-optional dependency named but not built by this ADR: a witness reference
  implementation, so "any independent party can run one" is a real, exercisable capability at
  implementation time, not merely a theoretical option.
- A new, required, non-optional dependency named but not built by this ADR: tenant key custody and
  recovery infrastructure (§7), needed before any genuinely tenant-private data can safely use this
  design's encryption mechanism.
- `AGENTS.md`'s "another database" prohibition is lifted **only** for the specific mechanism this ADR
  describes (an additive append-only table on the existing Postgres instance, plus a verifiability
  export protocol) — it does not authorize a broader class of new storage engines or database
  additions, and any future proposal to add a genuinely separate storage system needs its own review
  against this ADR's reasoning, not an assumption that this door is now fully open.
- `internal/metering`'s existing evidence pipeline is unmodified; this ADR's design is intentionally
  compatible with it (§5's `chain_anchor` shape is a superset of what `metering_evidence` already
  implicitly carries) rather than requiring its migration.

## Open questions for the accepting reviewer

- **Is detection-not-prevention (§9) an acceptable answer for Control-Plane-originated events until
  #34 lands**, or does the reviewer want this ADR to wait on ADR-017/#34 being accepted first so
  write-path authorship, not just verification, is decentralized from day one? This ADR judged
  standing alone as the stronger, ADR-038-consistent choice, but the reviewer may weigh the residual
  centralized-authorship gap differently.
- **Is envelope encryption with entirely unspecified tenant key custody/recovery (§7) an acceptable
  mechanism to accept now**, given the actual key-management system it depends on is explicitly not
  designed here? The alternative — waiting for a full tenant-identity/key-custody ADR before
  accepting any part of this design — would block #33 indefinitely on a separable, harder problem;
  this ADR assumes that trade-off is acceptable, matching ADR-029 §12's identical assumption for its
  own analogous gap, but that assumption is the reviewer's to confirm.
- **Should on-chain checkpoint commitment of the event log's hash-chain state (Out of scope) be
  pulled into this ADR's scope**, strengthening §9's "detection after the fact" into something closer
  to "prevention," at the cost of new on-chain state and a new governance question (who may commit a
  checkpoint, and does that just relocate the single-key trust problem rather than solve it)? This
  ADR judged that a separable, real strengthening worth its own scrutiny rather than folding it in
  here, but it is a legitimate alternative the reviewer may prefer to see designed now.
- **Is `SnapshotInterval`/`RetentionWindow` left as unfixed, governed constants (§8) — rather than
  concrete proposed values, unlike ADR-038's own `MaxSchedulableProviders = 1024` precedent of
  proposing a concrete-if-placeholder number — the right level of specificity for this ADR**, or
  should this document propose starting values the way every other governed-constant-introducing ADR
  in this roadmap already has?
- **Is extending the already-reserved, currently-unused `EventEnvelope` message (§10) the right
  home for this design's wire shape**, versus a wholly new message type that leaves `EventEnvelope`
  untouched for whatever it was originally reserved for? This ADR chose the smaller-surface-area
  option (reuse a dormant reservation rather than add a second, overlapping concept) but no record of
  `EventEnvelope`'s original intended purpose exists in this codebase to confirm that reuse is safe.

## Verification

Checked against source before writing, every file named below read in full unless noted: `AGENTS.md`
(permanent prohibitions, frozen architecture, ADR-gate framing, in full); `docs/adr/
012-decentralization-roadmap-and-trust-boundaries.md` (full file — §2 trust/threat table, §3 data
classification table including "Workload metadata"/"Secrets"/"Audit evidence" rows, §4 cross-cutting
guarantees including the replay-protection and conflict-resolution rules this ADR follows literally,
§6 gate table's exact "ADR-024... Unblocks #33" row and both renumbering-policy "Consequences"
entries, §7 rollback rule); `gh issue view 33` and `gh issue view 34` (full text, every acceptance
criterion cross-checked against a specific Decision subsection above); `control-plane/internal/
workloadapi/postgres.go` (full file — `ClaimNext`'s row-lock fencing, `AssignLease`'s Serializable
transaction, every `Mark*`/`RetryLater` call's optimistic-concurrency `WHERE` clause, confirming the
single-writer-per-subject pattern §1's CRDT rejection is grounded on); `control-plane/internal/
orchestrator/worker.go` (full file — `processOne`'s full state machine, `decodeDefinition`'s
in-process plaintext decode confirming §7's honest scoping, every `PersistentStore` call site §11's
dual-write proposal touches); `control-plane/internal/wireguard/wireguard.go` and `control-plane/
internal/agentmanager/directory.go` (full files — confirmed both stay reconstructible caches,
untouched by this ADR); `control-plane/migrations/` (every filename listed, `000004_workloads.sql`
and `000016_metering_evidence_and_invoices.sql` read in full — the `CHECK` constraints §1's CRDT
rejection cites, and `metering_evidence`/`metering_evidence_rejections`'s exact append-only,
sequenced, signed shape this ADR generalizes); `control-plane/internal/metering/signing.go` (full
file — the domain-separated canonical-byte-encoding pattern this ADR's `event_id`/signature
construction follows directly, and the reasoning for why a hand-rolled encoding, not a proto marshal,
is used); `control-plane/internal/blockchainbridge/registrar.go` (confirmed the bridge account's
signing key is Ed25519, `"Substrate signer key must use Ed25519"` at line 384, the key this ADR's §3
reuses for Control-Plane-originated event signing); `blockchain/pallets/lease/src/lib.rs` (full file
— `Lease`'s strict transition table, `LeaseCreated`/`LeaseStateChanged` events this ADR's §5 anchors
against, confirming no new on-chain state is required); `blockchain/pallets/network-validator/
src/lib.rs` (module doc and event/storage definitions — the independently-operated,
stake-bonded-validator precedent for "genuine multi-party attestation already exists in this
codebase," grounding §9's provider-attested-events claim); `blockchain/pallets/provider-registry/
src/lib.rs` (grepped — `Provider.public_key`, `ProviderStatus`, confirming the existing on-chain key
registry this ADR's provider-signature verification reuses); `docs/adr/
029-metering-billing-escrow-settlement.md` (full file — the signed-evidence, hash-anchored,
domain-separated-encoding precedent §1-§6 build on directly, and its own honest-gap-naming
discipline this ADR's §7/§9 follow); `docs/adr/038-on-chain-workload-orchestration.md` (full file —
the "verifiability, not consensus-state placement, is what makes this decentralized" reasoning this
ADR's entire three-level framing and §9 apply to the operational event history instead of scheduling
decisions, `scheduling_block_hash`'s exact precedent §5 generalizes, and its own numbering-note and
partial-fulfillment-of-a-gate format this document's Status section follows); `docs/adr/
036-provider-slashing-economics.md` and `docs/adr/037-content-addressed-frontend-distribution.md`
(numbering-note precedent this document's own numbering note follows); `protocol/proto/openinfra/
shared/v1/shared.proto` (`WorkloadDefinition`/`ResourceRequirements`/`WorkloadConstraints`/
`EventEnvelope` message definitions in full — confirmed `EventEnvelope`'s exact current shape and
zero real consumers via `grep -rl EventEnvelope control-plane --include=*.go`, confirmed no
env-var/secrets field exists anywhere on the wire today, grounding §7's honest scoping);
`protocol/proto/openinfra/agent/v1/agent.proto` (grepped for env/secret fields, confirmed absent);
`docs/adr/` directory listing against fresh `origin/main` (`git ls-tree`, confirming `038` is the
highest existing number) and `gh pr list -R flo2517/openinfra --search "docs/adr" --state all` plus
local/remote branch listing (confirming no open PR or unmerged branch claims `039`).

Refs #33. Related: #34 (multi-Control-Plane and scheduling relays — explicitly decoupled, §9; this
ADR's witness mechanism is forward-compatible with, but does not require, #34's acceptance), ADR-012
(§3 data classification — this ADR's target for "Workload metadata"/"Audit evidence", §4
replay-protection and conflict-resolution rules followed literally, §6 gate table, §7 rollback
discipline), ADR-011 (Network Validator precedent for genuine independent, stake-bonded, signed
attestation — the model §9 names as already real for provider-attested events), ADR-029 (metering
evidence's already-shipped signed-append-only-log precedent this ADR generalizes, and its
domain-separated canonical-encoding convention reused directly), ADR-038 (the "verifiability, not
consensus-state placement" decentralization principle this ADR applies to the operational event
history instead of scheduling decisions, and `scheduling_block_hash`'s precedent generalized by
§5's `chain_anchor`).
