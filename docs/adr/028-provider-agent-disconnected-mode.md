# ADR-028: Provider Agent disconnected mode and durable command reconciliation

## Status

Accepted (by the repository owner, explicitly, relayed in-session — after reviewing a full summary
of this ADR's decisions and their reasoning, then confirming to proceed with implementation).

Originally written by Claude Code, autonomously, in response to issue #16, and held as Proposed per
the convention established by ADR-016/018/025/026/029: it decides what an autonomous Provider Agent
is and is not allowed to do when it cannot reach the Control Plane — a real security/liveness
boundary, not a narrower technical decision. Nothing here is implemented yet by this ADR itself;
issue #16 is unblocked by this acceptance and now carries the implementation work.

**No prior spec exists.** `docs/` was searched for an existing "disconnected mode" design before
writing this — none exists, despite issue #16's phrasing ("the specified... mode"). This ADR *is*
the spec, not a write-up of one that already existed.

## Context

**What already exists and this ADR builds on, verified against source, not assumed:**

- **Local durable workload state already exists and already survives restart.**
  `agent-core::local_state::LocalState` (`provider-agent/crates/agent-core/src/local_state.rs`) is
  a `sled`-backed store keyed by `workload_id`, holding `WorkloadRecord { workload_id, lease_id,
  image, spec_hash, container_id, phase, egress_mbps, rate_limited }`. `reserve_workload` is
  already idempotent by design: a retried request for the same `workload_id` with the same
  `spec_hash` returns `Reservation::Existing` rather than erroring or double-provisioning; a
  different `spec_hash` under the same `workload_id` is rejected as `WorkloadConflict`. This is
  most of "persist bounded workload state and last acknowledged command locally" already built —
  this ADR's job is to close the specific gaps below, not to invent the mechanism from nothing.
- **Restart recovery already exists.** `agent-executor`'s `recover()` (`provider-agent/crates/
  agent-executor/src/lib.rs:435`) runs at Agent startup, reads every persisted `WorkloadRecord`, and
  reconciles it against what Docker actually reports (`engine.inspect`): a container still running
  is re-marked `Running` (and has its `tc` rate limit reapplied if it was lost, ADR-025 §3); a
  container the Agent can no longer find is marked `Lost`, an explicit terminal-but-honest phase —
  never silently dropped, never reported as if it were still fine. This is the existing answer to
  issue #16's "restart" test case at the container level; this ADR extends it to cover the
  Control-Plane-relationship state that sits alongside it (last acknowledged command, lease
  expiry), which `recover()` does not currently touch.
- **Capacity is already bounded by an operator-configured cap.** `ExecutorSettings::max_workloads`
  defaults to 8 (`agent-core/src/lib.rs`) and `reserve_workload` enforces it by counting records
  whose `phase.consumes_capacity()` before accepting a new one. Durable workload state is therefore
  already disk-bounded in proportion to this existing, already-enforced cap — a handful of small
  `WorkloadRecord`s, not an unbounded log.
- **Commands are unary and Control-Plane-initiated, not Agent-pulled from a queue.**
  `ProviderAgentService.Deploy`/`Stop` (`protocol/proto/openinfra/agent/v1/agent.proto`) are called
  *by* the Control Plane *into* the Agent's own gRPC server (`agentmanager.Client.DeployAndConfirm`,
  `control-plane/internal/agentmanager/client.go`). There is no Agent-side inbound message queue to
  bound — a genuinely partitioned Agent simply never receives a call at all; the connection attempt
  itself fails on the Control Plane's side. What needs bounding is not a receive queue but the
  Agent's own durable record of *what it has already done*, so a redelivered command after a
  partition heals is handled idempotently rather than reapplied.
- **The Agent's heartbeat loop and its own gRPC server already share one process and one
  `LocalState` handle.** `agent-cli/src/main.rs`'s `handle_start` spawns the background heartbeat
  task and builds the `ProviderAgentServiceServer` in the same `tokio` runtime, both holding
  `Arc<LocalState>`. This ADR's "reject new work while disconnected" mechanism can therefore be
  simple in-process shared state — no cross-process coordination needed, confirmed by reading
  `handle_start` directly rather than assumed.
- **Nothing today lets the Agent know when a lease actually ends.** `DeployRequest` (`agent.proto`)
  carries only `workload_id`, `lease_id`, `image`, and `ResourceLimits` — no expiry timestamp,
  despite `shared.proto`'s `Lease` message already having `start`/`end` fields that are simply never
  sent to the Agent. This is a real, concrete gap this ADR must close, not a detail to gloss over:
  "continue existing workloads according to an explicit lease policy while disconnected" is
  impossible for the Agent to do correctly without knowing, locally, when its own lease ends.
- **The Control Plane already refuses to dispatch to a stale-heartbeat provider.**
  `agentmanager.AgentManager.Deploy` (`control-plane/internal/agentmanager/manager.go`) already
  checks `conn.Status != ACTIVE || time.Since(conn.LastSeen) > heartbeatTimeout` before calling
  through. Heartbeat cadence is 15s, Redis-side TTL is 45s (`providerjoin.defaultHeartbeatInterval`/
  `defaultHeartbeatTTL`). Both numbers are reused below rather than inventing new ones.
- **A directly comparable retry/backoff precedent already exists and is already accepted.**
  `providerjoin.Reconciler` (`control-plane/internal/providerjoin/reconciler.go`) already retries
  failed chain registrations with exponential backoff (base 5s, doubling, capped at 10 minutes,
  terminal after 10 attempts). This ADR reuses the same backoff shape for the Agent's own
  reconnection attempts, rather than choosing new numbers with no precedent.

**Checked against `AGENTS.md`/ADR-012 §6 before designing anything, the same discipline ADR-018 used
for its own gate check:**

- **"Runtime orchestration" (`AGENTS.md`, gated by ADR-019, unblocks #50/#62) does not apply.**
  ADR-019's gate is about scheduling/placement logic evaluated somewhere new — deciding *where* or
  *what* to run. Nothing in this ADR gives the Agent a new placement decision to make: it continues
  running exactly the containers the Control Plane already told it to run, under the exact lease
  terms already communicated, and it accepts no new work while disconnected. "Keep doing what you
  were already authorized to do, and refuse anything new until reconnected" is the deliberate
  opposite of autonomous orchestration, not a smaller version of it. No gate needs lifting.
- **"Direct Agent-to-chain access" (gated by ADR-020, unblocks #53–#56) does not apply.** The Agent
  never talks to the chain today, connected or disconnected, and nothing in this ADR changes that —
  disconnection from the *Control Plane* is not proximity to the chain. This ADR does not propose
  any chain-facing capability, bounded or otherwise.
- **No other §6 gate reads on this topic.** Checked line by line: ADR-017 (multi-Control-Plane),
  ADR-021 (content-addressed storage), ADR-022 (TEE), ADR-023 (governance), ADR-024 (replicated
  off-chain data plane) — none apply. This is Stage 0 resilience hardening (milestone v1.0, per the
  issue's own tag), matching ADR-012 §5's description of what v1.0 is for: hardening Stage 0, not
  decentralizing past it.

## Decision

### 1. Detecting disconnection

The Agent declares itself **disconnected** after **3 consecutive failed heartbeat attempts**
(~45s at the existing 15s cadence) — chosen specifically to match the Control Plane's own existing
staleness window (`defaultHeartbeatTTL` = 45s = 3× `defaultHeartbeatInterval`), so both sides agree
on the same boundary rather than each independently guessing when the other has given up. A single
transient failure does not trip disconnected mode — matches the same tolerance-for-noise reasoning
`AllowlistClientCertVerifier`/heartbeat-freshness code elsewhere in this codebase already applies
before treating something as truly gone. "Failed" includes any error from the heartbeat call: a
network error, an unreachable Control Plane, an expired mTLS certificate (ADR-027 composes here
directly — an unrenewed expired leaf certificate is one concrete way into this exact state), or a
non-2xx gRPC status.

Reconnection is retried indefinitely at the reused `Reconciler` backoff shape — base 5s doubling to
a 10-minute cap — never permanently giving up, because the Agent has no other job once disconnected
besides trying to stop being disconnected and honoring the lease-expiry policy below. This is
distinct from ADR-027's own retry loop for certificate *renewal specifically*, which does stop once
the certificate expires; the two loops interact (an expired cert makes every reconnection attempt
fail until renewal or manual intervention succeeds) but are not the same loop.

### 2. What the Agent does and does not do while disconnected

- **Continues running already-deployed workloads, unmodified.** Docker containers do not require a
  live Control Plane connection to keep running, and nothing in this ADR adds a mechanism that
  could stop them beyond the lease-expiry enforcement in §3. No code path introduced here can pause,
  restart, or otherwise disturb a healthy running container just because heartbeats are failing.
- **Refuses new work.** `Deploy` on the Agent's own gRPC server consults an in-process
  "disconnected since" marker (set by the same background task that owns the heartbeat loop,
  read by the request handler — both already share `Arc<LocalState>` and run in one process, so no
  new IPC is needed) and returns `FAILED_PRECONDITION` with an explicit "agent is disconnected from
  the Control Plane, refusing new work" message the moment 3 consecutive heartbeat failures have
  been recorded — never a silent timeout, never a fabricated success. This is deliberately a
  one-way gate for *new* commitments only.
- **`Stop` is always accepted, regardless of connection state.** There is never a safety reason to
  refuse "stop this workload" — refusing it would make disconnection strictly more dangerous, not
  less. This asymmetry matters specifically for the case where the partition is one-directional
  (the Agent cannot reach the Control Plane outbound, e.g. asymmetric routing/DNS, but the Control
  Plane can still open an inbound connection to the Agent's server) — winding down is always safe,
  taking on new commitments is not.
- **Never fabricates Control Plane acknowledgement.** `agent-core::local_state::WorkloadPhase`
  (`Provisioning`/`Starting`/`Running`/`Stopping`/`Stopped`/`Failed`/`Lost`) is already, entirely, a
  vocabulary of *locally observed* truth — it contains no phase that claims Control-Plane-side
  confirmation, and this ADR does not add one. This invariant is stated explicitly here as
  something every future change must preserve: nothing this ADR introduces may synthesize a value
  that presents an unconfirmed action as Control-Plane-confirmed (e.g., no locally-invented
  "lease renewed" or "deployment acknowledged" state that wasn't actually returned by the Control
  Plane). `DeployResponse.success` continues to mean exactly what it means today — the Agent's own
  local confirmation that the container is actually running — and disconnection changes nothing
  about that meaning; disconnection only ever produces the explicit refusal above, never an
  optimistic guess.

### 3. Lease policy: local, deterministic, bounded by the lease's own term — not by an arbitrary timeout

**The gap this closes:** `DeployRequest` today carries no lease expiry, so the Agent has no way to
know, locally, when it must stop a workload on its own. This ADR adds `lease_end`
(`google.protobuf.Timestamp`) to `DeployRequest`, sourced from the `Lease.end` the orchestrator
already holds in Postgres before it ever calls `Deploy`
(`control-plane/internal/orchestrator/worker.go`) but today never forwards. `WorkloadRecord` gains
a matching persisted `lease_end` field (`#[serde(default)]`, matching the existing backward-compat
convention `egress_mbps`/`rate_limited` already use, so records written before this field existed
still deserialize).

**The policy itself, deliberately simple:** a background task (reusing the existing 15s heartbeat
cadence — no new timer, no new polling loop) compares each active `WorkloadRecord.lease_end`
against the Agent's local clock, with the same **2-minute clock-skew tolerance** already established
elsewhere in this codebase (`providerjoin.maxHeartbeatClockSkew`) rather than inventing a new
number. Once `lease_end` plus tolerance has passed, the Agent calls its own existing `stop()` path
— the same code `StopRequest` already drives — with no dependency on the Control Plane being
reachable. This runs **unconditionally**, connected or not: while connected, the Control Plane
normally sends an explicit `StopRequest` at lease end anyway, so local enforcement rarely fires
first; while disconnected, it is the only thing that fires, and having it always-on rather than
disconnection-conditional avoids a second code path that only gets exercised in the rare case,
which is exactly the kind of under-tested branch this repository's "no silent mocks, no placeholder
success paths" working method (`AGENTS.md`) warns against.

**No separate global "how long can the Agent stay disconnected" timeout is introduced.** The
authorized operating window is already exactly the union of its currently-held leases' own terms —
adding a second, arbitrary bound on top would either be redundant (shorter than the shortest lease,
achieving nothing) or wrong (longer than some lease, contradicting the lease's own authorization).
Once every currently-held lease has locally expired, the Agent has nothing left it is authorized to
run; it keeps retrying reconnection (§1) indefinitely, at the capped backoff, with zero running
workloads, until it reconnects or is restarted.

### 4. Reconciliation on reconnect: status-first, by construction, not as a separate protocol step

**Design choice: every heartbeat carries a full workload-state snapshot, not just the first one
after a reconnect.** `HeartbeatSigningPayload` (`control_plane.proto`) gains a bounded repeated
field, `WorkloadStatusSummary { workload_id, phase, container_id, spec_hash }`, one entry per
locally-known workload (bounded by the same `max_workloads` cap as `LocalState` itself — 8 by
default, operator-configurable, never unbounded). This is deliberately **not** a special "resuming
after disconnect" message with its own detection logic and its own bug surface; it is simply what
every heartbeat already contains, always, at negligible marginal cost given the existing cap. The
reconnect case is then not a special protocol step at all — it is just "the first heartbeat that
succeeds after some failed ones," carrying exactly the same payload shape as every other heartbeat,
which is precisely what "status-first" as stated in the issue's acceptance criteria means in
practice: the Agent's actual observed state rides on the very call that re-establishes contact, not
a step that happens after new commands might already have been dispatched.

**Reconciliation is synchronous inside `ReportHeartbeat`, not a separate async pass.** The Control
Plane's existing `ReportHeartbeat` handler (`providerjoin.Service.ReportHeartbeat`) is extended to
diff each reported `WorkloadStatusSummary` against its own `workloads` table row and correct drift
using the **existing** workload state machine (`WORKLOAD_STATE_*` in `control_plane.proto`) — e.g.
Control Plane believed `DEPLOYING`, Agent reports `Running` → advance to `RUNNING`; Control Plane
believed `RUNNING`, Agent reports `Lost`/`Failed` → mark `FAILED` and let the **existing**
orchestrator retry/failure-reporting path take over. No new orchestration logic is introduced here
— this reuses the state machine and transition logic that already exists for every other state
change; it is only newly *fed* by the Agent's own report instead of solely by the orchestrator's own
actions. Because this reconciliation completes before `ReportHeartbeat` returns its response, and
`internal/orchestrator`'s dispatch path only ever acts on the Postgres state that reconciliation
just updated, "the Control Plane never dispatches a new command against stale state" holds by
construction, not by a race-prone ordering convention layered on top.

**Idempotency for redelivered commands:**

- **`Deploy` is already idempotent** via `reserve_workload`'s existing `spec_hash` comparison
  (`Reservation::Existing` for a retried identical request, `WorkloadConflict` for a genuinely
  different one under the same `workload_id`) — no change needed, confirmed by reading
  `local_state.rs` directly.
- **`Stop` gains the same property explicitly.** A `Stop` call for a `workload_id` that is already
  `Stopped`, `Failed`, or unknown to `LocalState` returns success (not an error) — stopping
  something that is already stopped, or that never existed from this Agent's point of view, is not
  a failure condition. This closes the "duplicate command" test case the issue names for the `Stop`
  side, which today has no explicit idempotency contract stated anywhere.

### 5. Partition vs. genuine death: explicitly not distinguishable, and this ADR does not pretend otherwise

Neither side can tell, from a stopped heartbeat alone, whether the Agent process died, the host is
unreachable, or the network between them is partitioned in one or both directions. This is stated
plainly rather than papered over, the same honesty ADR-012 §2 already required of "operator-level
collusion" and "bootstrap centralization": *not solved here*. The concrete, deliberately narrow
consequence: the Control Plane's only defensive action against a provider that stays disconnected
indefinitely is what already exists — stop scheduling new work to it, per `agentmanager.Deploy`'s
existing staleness check — and let §3's lease-expiry policy eventually reclaim the workload's
resources on the Agent's own side, whether or not the Agent ever reconnects. **This ADR does
not add any Control-Plane-side mechanism to detect, reassign, or migrate a disconnected provider's
workloads to a different provider.** That is auto-healing/migration territory (#62), explicitly
gated behind ADR-019 (on-chain orchestration) per ADR-012 §6, and this ADR does not attempt to get
ahead of that gate. A tenant whose provider goes permanently dark is, today and after this ADR,
left with an eventually-expired lease and no automatic replacement — an honest, visible gap, not a
silently assumed-away one.

## Consequences

- Proto changes needing the standard `AGENTS.md` consumer analysis before implementation:
  `DeployRequest.lease_end`, and `HeartbeatSigningPayload.workload_status` (the new bounded
  `WorkloadStatusSummary` repeated field). Consumers: `agent-cli`/`agent-executor` (producer of the
  heartbeat field, consumer of `lease_end`), `internal/orchestrator` (must start populating
  `lease_end` from the `Lease` row it already reads before calling `Deploy`), `providerjoin.Service`
  (new reconciliation logic inside `ReportHeartbeat`), and `internal/protocolcontract` (new
  contract-conformance cases).
- `WorkloadRecord` gains a persisted `lease_end` field — a `local_state.rs` schema change,
  non-breaking via `#[serde(default)]`, matching the existing precedent from ADR-025 §3's
  `egress_mbps`/`rate_limited` additions.
- A new always-on background task in `agent-cli`'s long-running process (lease-expiry enforcement,
  §3) alongside the existing heartbeat-loop task — both already share `Arc<LocalState>`, so no new
  cross-task coordination primitive is needed beyond what `handle_start` already has.
- `agentmanager`/`agent-api`'s `Deploy` handler gains an explicit disconnected-mode refusal branch;
  `Stop` gains an explicit idempotency contract for already-stopped/unknown workloads.
- `providerjoin.Service.ReportHeartbeat` gains workload-state reconciliation logic reusing the
  existing `WORKLOAD_STATE_*` machine — new code, but not a new state machine.
- This ADR does not change `agentmanager.AgentManager`'s existing staleness-based dispatch refusal
  or `Directory.ListSchedulableProviders`'s heartbeat-freshness filter — both already do the right
  thing for a disconnected provider (stop scheduling to it) with no changes needed.
- Explicitly does not add: any new global disconnected-mode timeout, any Control-Plane-initiated
  workload migration/reassignment, any Agent-to-chain capability, or any queue of inbound commands
  on the Agent side (none is needed, per the Context section's "unary, not pulled" analysis).

## Open questions for the accepting reviewer

- **The 3-consecutive-failure / 45s disconnection threshold.** Chosen to match the Control Plane's
  existing heartbeat-staleness window exactly, which is a real, defensible reason, but it has not
  been tested against real-world transient-failure rates (e.g. a flaky link that fails every third
  heartbeat indefinitely without ever reaching a clean 3-in-a-row). Worth watching once implemented.
- **Whether `Stop`'s new idempotency contract needs a distinguishable response** (e.g., a
  `StopResponse` field saying "was already stopped" vs. "stopped just now") **for operator/audit
  visibility**, or whether "success either way" is sufficient. This ADR takes the simpler answer
  (success either way, no new field) but flags the alternative as reasonable and not strongly
  argued against.
- **Whether workload-status reconciliation belongs on every heartbeat forever, or should shrink to
  a delta-only format once this ships and proves the always-full-snapshot approach's bandwidth cost
  is negligible in practice** (it should be, at `max_workloads` ≤ a handful of entries by default,
  but this ADR does not measure it).

## Verification

Checked against source before writing: `provider-agent/crates/agent-core/src/local_state.rs` (full
file — `WorkloadRecord`, `WorkloadPhase`, `reserve_workload`'s idempotency/conflict/capacity logic);
`provider-agent/crates/agent-executor/src/lib.rs` (`recover()` at line 435, `WorkloadPhase::Lost`
assignment, the ADR-025 §3 rate-limit-reapplication comment); `provider-agent/crates/agent-core/
src/lib.rs` (`ExecutorSettings::max_workloads` default of 8); `provider-agent/crates/agent-cli/
src/main.rs` (`handle_start`'s background heartbeat task and `AgentGrpcServer` construction sharing
one process and one `Arc<LocalState>`); `protocol/proto/openinfra/agent/v1/agent.proto` (full file —
`ProviderAgentService`, `DeployRequest`/`StopRequest`, confirmed no lease-expiry field exists);
`protocol/proto/openinfra/shared/v1/shared.proto` (`Lease` message's `start`/`end` fields, confirmed
never forwarded to the Agent); `protocol/proto/openinfra/controlplane/v1/control_plane.proto` (full
file — `HeartbeatSigningPayload`, `WorkloadState` enum, `ReportHeartbeatRequest`/`Response`);
`control-plane/internal/providerjoin/service.go` (full file — `ReportHeartbeat`,
`defaultHeartbeatInterval`/`defaultHeartbeatTTL`/`maxHeartbeatClockSkew`);
`control-plane/internal/providerjoin/reconciler.go` (full file — the backoff-shape precedent
reused for reconnection retries); `control-plane/internal/agentmanager/manager.go` (full file —
`AgentManager.Deploy`'s existing staleness check, `heartbeatTimeout`); `control-plane/internal/
agentmanager/directory.go` (`ListSchedulableProviders`'s heartbeat-freshness filter);
`control-plane/internal/agentmanager/client.go` (`DeployAndConfirm`, confirming Deploy/Stop are
Control-Plane-initiated unary calls, not Agent-pulled); `control-plane/internal/orchestrator/
worker.go` (confirms the orchestrator already holds `Lease` rows, including `end`, before calling
`Deploy`, and never forwards them); `docs/adr/012-decentralization-roadmap-and-trust-boundaries.md`
(§2's honest-gap framing for operator collusion/bootstrap centralization, mirrored in this ADR's §5;
§5, §6 — confirmed no gate applies); `docs/adr/018-slashing-and-economic-penalties.md` (the gate-
check discipline this ADR's Context section mirrors); `docs/adr/025-bandwidth-usage-reporting-and-
rate-limit-enforcement.md` §2 (the `#[serde(default)]` backward-compat precedent reused for
`lease_end`); `AGENTS.md` (frozen-architecture, prohibited-changes, and working-method sections, in
full).

Refs #16. Related: ADR-012 §2/§6 (honest-gap framing, gate-check discipline), ADR-018 (gate-check
discipline precedent), ADR-025 §2/§3 (heartbeat-extension and `#[serde(default)]` precedents),
ADR-027 (mTLS PKI hardening — an unrenewed expired certificate is one path into the disconnected
state this ADR governs; the two proposals compose but are independently mergeable).
