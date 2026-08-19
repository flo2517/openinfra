# ADR-025: Bandwidth usage reporting and workload rate-limit enforcement

## Status

Accepted (by the repository owner, explicitly, relayed in-session — including §3's `CAP_NET_ADMIN`
grant to the Agent process, the reason this was held for explicit sign-off rather than
self-accepted).

**Implementation status:** §1 (multi-probe measurement) is implemented — it needed no new
privilege and no proto change, so it lands first. §2 (signed usage summaries over the heartbeat)
and §3 (host-side `tc` enforcement, the `CAP_NET_ADMIN` part) are separate, larger slices: §2
changes `protocol/proto` and therefore needs the consumer analysis `AGENTS.md` requires, and §3
changes what the packaged Agent deployment is allowed to do. Sequenced, not skipped.

## Context

Issue #73 is the remainder of #30 once its first slice (units, capability reporting, scheduler
reservation) and ADR-015 (independent validator-run active bandwidth probing, `MeasureBandwidth`
RPC, accepted and implemented — confirmed in `agent-api`, `internal/networkvalidator/bandwidth.go`)
landed. Re-checking #73's remaining acceptance criteria against the current code:

- **"Independent validators run abuse-resistant multi-point tests rather than trusting the
  provider's self-reported figures."** Mostly already true: `MeasureBandwidth` evidence flows
  through the same `submit_evidence`/`close_round` committee-quorum-trimmed-mean pipeline every
  other `ScoreDimension` already uses (`pallet-network-validator`), so multi-*validator*
  independence is inherited for free, not a gap. What ADR-015 does leave single-shot is
  multi-*point*: one probe per round, which a provider could game by detecting a probe and
  temporarily boosting bandwidth for its duration. §1 closes that narrow remainder as an
  implementation-level parameter, not a new mechanism.
- **"Agent reports bounded signed usage summaries (not just a declared static capacity)."** Still
  entirely missing. ADR-015's `MeasureBandwidth` is a validator-initiated on-demand probe: it says
  nothing about what a workload is actually using during normal operation, only what the *link*
  can do when explicitly tested. §2 designs this.
- **"Workload-level rate limits are not enforced."** Still entirely missing: `ContainerSpec`
  (`agent-executor/src/lib.rs`) carries `memory_bytes`/`nano_cpus`/`pids_limit` into `HostConfig`,
  which Docker enforces natively — there is no equivalent Docker `HostConfig` field for network
  throughput, so a workload's reservation today is scheduling-side bookkeeping only, never
  actually throttled. §3 designs this.
- **"WireGuard overhead and regional endpoint selection are not accounted for."** Both are
  parameter/formula gaps in already-accepted mechanisms (ADR-015's scoring, the scheduler's fit
  score), not new architecture — §4 settles them without a new mechanism.
- **Congestion, asymmetric links, spoofed results, partition test coverage** — a testing
  obligation once the above ship, enumerated in §5, not an architecture decision on its own.

## Decision

### 1. Multi-point probing: a governed repeat count, not a new protocol

`MeasureBandwidth` (ADR-015) stays a single-RPC probe. What changes is call-site behavior in
`internal/networkvalidator/bandwidth.go`: a new governed constant, `BandwidthProbesPerRound`
(default 3, small enough to keep the challenge loop's per-round latency budget sane), each probe
temporally spread within the round rather than back-to-back (a fixed jitter window derived from
`(provider, round, probe_index)`, the same deterministic-seed pattern `committee()` already uses,
so a provider cannot predict probe timing from round start alone). The evidence submitted is the
**minimum** of the probes' measured Mbps in each direction, not the mean — a provider gaming one
window still gets caught by whichever probe it didn't anticipate; only a provider that sustains
real capacity across all probes passes. This is a bounded implementation parameter on an already-
accepted mechanism, not a new RPC or new trust boundary.

### 2. Agent-reported signed usage summaries: periodic, bounded, cumulative-counter-based

A new field on the existing heartbeat path rather than a new RPC — `ReportHeartbeatRequest` already
carries liveness data every ~15s (ADR-013 §3 already extends this response direction for the
validator allowlist push; this extends the *request* direction). Add a repeated
`WorkloadBandwidthUsage { workload_id, ingress_bytes_total, egress_bytes_total, window_started_at,
signature }` — cumulative (monotonic) counters per workload since container start, not a delta,
so a single dropped heartbeat cannot be exploited to hide usage between reports (the Control Plane
computes deltas across successive reports itself and treats a counter decrease as a signal to
discard that workload's data point rather than trust it, the same defensive posture already used
elsewhere for untrusted input). Signed the same way `solve_challenge`/`MeasureBandwidth` responses
already are (Ed25519 over a domain-separated byte layout, exact bytes pinned by the implementing
PR). Source of the counters: Linux per-interface byte counters for the workload's veth pair
(`/sys/class/net/<veth>/statistics/{rx,tx}_bytes`), which `agent-executor` already has to name at
container-create time to apply §3's `tc` rule against — the same lookup serves both.

**What this is not:** a billing-grade metering system. It is a bounded, self-reported (Agent-side)
telemetry stream, useful for capacity planning, dashboards, and detecting workloads that
persistently exceed reservation — not yet cross-checked by an independent third party the way
`MeasureBandwidth` evidence is. Treating it as authoritative for anything financial is explicitly
deferred to the metering/settlement work (milestone v1.1, issue #19/#21), consistent with how
ADR-011 already keeps reward/slash accounting separate from lease settlement.

### 3. Workload rate-limit enforcement: host-side `tc` against the workload's veth, keyed by lease

Docker's `HostConfig` has no bandwidth field (confirmed: `bollard::models::HostConfig`, the crate
already in use, exposes none); this is why nothing enforces the reservation today. `agent-executor`
gains a fourth quota alongside memory/CPU/PIDs: at container start, after Docker allocates the
container's veth pair, run `tc qdisc add dev <veth> root tbf rate <reserved_mbps>mbit burst
<bounded> latency <bounded>` (token bucket filter — simplest qdisc that gives a hard ceiling
without needing classful HTB's added complexity for a single class), and tear it down when the
veth is removed (container stop already triggers this by removing the interface; no separate
cleanup call needed). This targets **egress only** at the host's end of the veth by default —
symmetric ingress shaping needs an `ifb` redirect, more moving parts for a benefit that matters
less in the MVP's target failure mode (a workload flooding *outbound* traffic and starving other
workloads on the same host NIC) — noted as a known asymmetry, not solved here.

**Privilege consequence, stated plainly:** running `tc` against a host network interface needs
`CAP_NET_ADMIN` on the Agent process (not the workload container — `no-new-privileges`,
`cap_drop: ALL` on the workload's own `HostConfig` are unaffected, this is entirely the Agent's own
process boundary, already trusted with the Docker socket itself via `docker-socket-proxy` per the
existing deployment). This is why this ADR is left Proposed rather than self-accepted: it is a new
standing capability for the Agent process, and deserves the same explicit sign-off ADR-016 gave
dashboard tenant boundaries.

### 4. WireGuard overhead and regional endpoint selection: parameters on existing mechanisms

- **WireGuard overhead**: ADR-015 §5 compares measured Mbps against `ResourceCapability.Bandwidth`
  with a flat 70% tolerance. When a workload is lease-gated behind the ADR-010 overlay, apply an
  additional governed constant, `WireGuardOverheadBps` (default 500 basis points = 5%, reflecting
  typical WireGuard framing/encryption overhead), subtracted from the tolerance threshold before
  comparison — so a provider is not penalized for overhead the overlay itself imposes. No new
  mechanism; a second constant read alongside the existing tolerance factor.
- **Regional endpoint selection**: superseded by
  [ADR-026](026-availability-zone-selection.md). The RTT-based design sketched in the paragraph
  this replaces turned out to solve the wrong problem — "regional endpoint selection" in an
  infrastructure-scheduling context means a workload naming a zone and being placed only on a
  provider in that zone (a placement constraint the requester declares), not a network-quality
  signal a validator measures. ADR-026 builds the actual feature; RTT-based latency-aware routing
  remains a distinct, still-open idea named there as future work, not resurrected here.

### 5. Required test coverage (implementation checklist, not new decisions)

- Congestion: two workloads sharing one provider's link, one saturating egress — the other's
  reservation still holds via §3's `tc` ceiling.
- Asymmetric links: ingress and egress measured and scored independently (already true of
  ADR-015's two-figure result), verify a link that passes one direction and fails the other
  produces `score_bps = 0` for `Network`, not an averaged partial pass.
- Spoofed results: a `MeasureBandwidth` response with a signature that doesn't verify, or a
  `WorkloadBandwidthUsage` counter that decreases between reports, is rejected/discarded, not
  silently accepted.
- Partitions: a heartbeat that never arrives leaves `WorkloadBandwidthUsage` absent for that
  window — the Control Plane must render this as "no data," never as "zero usage" (the same
  no-false-success discipline ADR-011/#29 already requires of the dashboard).

## Consequences

- `ReportHeartbeatRequest`/`Response` gain fields — proto change, needs the consumer analysis
  `AGENTS.md` requires (Control Plane and every Agent build) before it ships.
- The Agent process gains `CAP_NET_ADMIN` — a real, standing privilege increase or the packaged
  deployment, worth documenting in `deployments/` and the README's trust model, not just this ADR.
- `internal/networkvalidator`'s per-round latency budget grows roughly 3x for the `Network`
  dimension (§1's repeated probing) — bounded and governed, not unbounded.
- Billing/settlement continues to treat bandwidth as out of scope until milestone v1.1's metering
  work; §2's usage summaries are explicitly not wired to anything financial yet.

## Verification

Checked against source before writing: `docs/adr/015-bandwidth-throughput-measurement.md` (full
text); `blockchain/pallets/network-validator/src/lib.rs` (`submit_evidence`/`close_round`/
`trimmed` shared by every dimension); `control-plane/internal/networkvalidator/bandwidth.go` (230
lines, single-probe-per-round today); `provider-agent/crates/agent-executor/src/lib.rs`
(`ContainerSpec`, `HostConfig` construction, no bandwidth field); `bollard` `HostConfig` (crate
version pinned `"0.15"` in `agent-executor/Cargo.toml`, confirmed no bandwidth-limit field exists
in that struct); `docs/adr/013-network-validator-daemon.md` §3 step 3 (existing heartbeat-response
extension precedent this ADR's §2 mirrors on the request side).

Refs #73. Related: ADR-015 (extended, not replaced), ADR-010 (WireGuard overlay), ADR-013 §3
(heartbeat extension precedent), #19/#21 (metering/settlement, where usage summaries eventually
feed billing).
