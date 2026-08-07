# ADR-013: Network Validator daemon — implementation architecture

## Status

Accepted.

**Implementation status (post-acceptance):** all five slices from §3 are
now implemented. Slice 5 (round closing/disputes) split across two
binaries by necessity, not by choice: `dispute_round` is directly signed
by the disputing validator's own account (`cmd/networkvalidator dispute`,
alongside slices 1/4's other directly-signed calls), but
`resolve_dispute` is `SuspensionOrigin`-gated (`EnsureRoot` in this
runtime) -- only the Control Plane's own bridge/sudo account can call it,
so it lives in `cmd/controlplane-admin resolve-dispute` instead, sudo-
wrapped the same way provider registration's `EnsureActive` already is.
`dispute_round` is deliberately a manual CLI action, never triggered by
the challenge loop itself (§9's own reasoning: an automated dispute on
every disagreement would just move the trust problem, not solve it). The
pallet's dispute_round also authorizes the scored *provider* to dispute,
not only a committee validator -- that path is real on-chain but not yet
reachable by any tool in this MVP, since a provider has no independent
chain-signing path (AGENTS.md's frozen rule: the Provider Agent never
talks to the chain directly). A future Control-Plane-proxied
`dispute_round_for`, mirroring `register_provider_for`'s already-accepted
delegation pattern, is the natural way to close that gap -- not attempted
here since it wasn't asked for.

## Context

ADR-011 accepted the Network Validator *protocol* (identity, stake, committee
assignment, evidence submission, aggregation, disputes, incentives) and the
pallet that enforces it (`pallet-network-validator`, `blockchain/pallets/
network-validator/`) is real: registration/exit/suspend/reinstate, quorum-
gated evidence submission with self-scoring and duplicate-submission
rejection, trimmed-mean aggregation into `pallet-reputation`, and disputes —
36+ tests, all real chain state, no scaffolding (issue #29 discussion).

What does not exist anywhere in the codebase is the Network Validator
itself: a process that registers a validator identity, discovers which
providers it is assigned to challenge, calls `SolveChallenge` against those
providers' Agents, evaluates the result, and submits `submit_evidence`/
`close_round`. `agent-api`'s `solve_challenge` handler has existed since
before this ADR (compute/storage/availability challenge types) but nothing
calls it. `pallet-network-validator::committee()`/`is_assigned()` are plain
`impl<T: Config> Pallet<T>` helpers, not exposed through a custom Runtime
API — there is no way for an off-chain client to ask the chain "am I
assigned to provider X this round" other than replicating the deterministic
`blake2(parent_hash, provider, round)` selection locally, which is by design
(ADR-011 §1: assignment is public once the block is known, not secret).

ADR-011 explicitly deferred to implementation: "the Control Plane's
validator-allowlist push mechanism to Agents" and, by omission, the daemon's
very existence, language, and deployment shape. This ADR closes those gaps.
It also surfaces and resolves one gap ADR-011 did not address: **how does an
independently operated Network Validator learn a provider's Agent network
endpoint at all?** `pallet-provider-registry::Providers` stores only
`(owner, public_key, status)` — no endpoint. `agent_endpoint` exists only in
the Control Plane's Postgres (from `BeginJoinRequest`), which an independent
third party has no access to today.

## Decision

### 1. Where this lives, and in what language

The daemon is `control-plane/cmd/networkvalidator`, a new Go binary in the
existing `control-plane` module — **not** a new top-level directory or a
Rust crate, for one concrete reason: `internal/blockchainbridge` already
has working, tested SCALE encoding/decoding, extrinsic construction, and
signing (`Registrar.submitSigned`/`signCall`/`finalizedAccountNonce`) built
and proven against this exact runtime across #38/#39/#48/#49/#64/#69/#70.
Rebuilding that in Rust to keep every chain-facing component in one
language would cost real time for zero protocol benefit — the validator is
a chain + gRPC client, not a consensus participant, so it carries none of
the runtime's `no_std`/floats/unchecked-arithmetic constraints that justify
Rust elsewhere in `AGENTS.md`.

This does **not** make the daemon part of "the Control Plane" as an
operator boundary: `cmd/networkvalidator` is independently buildable and
runnable, needs no Postgres/Redis, and authenticates to the chain with its
own operator-supplied key, never the bridge account's. An independent
operator clones the repo (or pulls a released binary) and runs one binary,
same as `agent-cli`.

### 2. Identity

A Network Validator's chain identity is an Ed25519 keypair, PKCS#8 PEM,
loaded the same way `blockchainbridge.NewRegistrarFromPKCS8File` already
loads the Control Plane bridge key. `Registrar` is generalized (it already
was: it's "an Ed25519 account that can sign and submit extrinsics," nothing
CP-specific in its low-level `signCall`/`submitSigned`) with new
validator-lifecycle and evidence methods alongside its existing lease/
provider-registry/resource-market ones. The bridge account and a validator
account are never the same key in any real deployment; nothing in the code
enforces that today beyond operational discipline, matching how nothing
stops a provider's key and the bridge's key from colliding either.

### 3. Sequencing (this ADR scopes all of it; implementation lands in slices)

1. **Identity and lifecycle** (first implementation slice, this issue):
   `register_validator`, `request_exit`, `withdraw_unbonded` as directly
   signed (not sudo-wrapped) extrinsics, plus a `status` command reading
   `Validators`/`ActiveValidatorSet` at the finalized head. Self-contained,
   depends on nothing else in this ADR, directly exercises ADR-011 §1's
   trust boundary ("validators submit their own signed extrinsics, not
   through the bridge") end-to-end for the first time.
2. **Agent endpoint discovery** (blocks step 4): the Control Plane gains a
   new, unauthenticated, read-only, rate-limited HTTP endpoint --
   `GET /api/v1/agent-endpoint/{provider_id}` on the existing dashboard HTTP
   listener (already public/read-only by design; see `internal/dashboard`)
   -- returning `{agent_endpoint, public_key}` for a provider whose
   `provider_id` (the sha256 hash already used everywhere) is given. This is
   not a new trust boundary: the same data already renders in the public
   dashboard's provider list, and `agent_endpoint` was never secret (an
   Agent's mTLS listener rejects any client without a Control-Plane-issued
   or -allowlisted certificate regardless of who knows its address).
   Rate-limited via the existing `internal/ratelimit` package, keyed by
   caller IP, to bound scraping cost -- not an auth boundary.
3. **Validator allowlist push to Agents**: extends the existing heartbeat
   response (`ReportHeartbeatResponse`) with a repeated list of active
   Network Validators' public keys, refreshed every heartbeat (~15s) the
   same way liveness already refreshes. The Agent's mTLS server gains a
   second `ClientCAs` pool entry class: accept a client certificate if it
   chains to the existing Control Plane CA *or* if the client's public key
   (extracted from the cert) is in the most recently pushed validator
   allowlist. A validator's own certificate is self-signed over its Ed25519
   chain key (no separate validator PKI, per ADR-011 §2's explicit
   decision) -- the Agent trusts the *key*, pushed by the Control Plane,
   not a CA chain, for this second client class.
4. **Challenge loop**: poll the finalized head; for each active round tick,
   recompute `committee(provider, round)` locally in Go (replicating the
   pallet's deterministic blake2 selection -- both sides derive the same
   value from public inputs, so no chain call is needed to check
   self-assignment beyond reading `parent_hash`); for each provider this
   validator is assigned to, resolve its endpoint (step 2), call
   `SolveChallenge` over mTLS (step 3) for each in-scope dimension, score
   the result, and call `submit_evidence`. Requires extending
   `SolveChallengeRequest.Type` with `TYPE_NETWORK`/`TYPE_RELIABILITY`
   (ADR-011 §2) -- proto work, its own slice.
5. **Round closing and disputes**: `close_round` once quorum is visible;
   `dispute_round` as an explicit operator CLI action, not automated (a
   validator disputing algorithmically on every disagreement would just
   move the trust problem, not solve it -- disputes stay a deliberate,
   attributable human action for the MVP).

Slices 2-5 are substantial and are **not** part of this ADR's accompanying
implementation PR -- tracked as issue #78, in this priority order, since
each genuinely blocks the next (no endpoint discovery -> no challenge calls
possible; no allowlist push -> every challenge call gets mTLS-rejected by
the Agent).

## Consequences

- `internal/blockchainbridge.Registrar` becomes shared infrastructure for
  two different account roles (CP bridge, Network Validator), not
  CP-bridge-only as its doc comments previously implied -- those comments
  need updating as part of the first slice's PR.
- The dashboard's HTTP listener gains a second, narrower public endpoint
  beyond the existing overview JSON. It carries the same "never secret,
  bounded, rate-limited" properties the existing `/api/v1/overview` and
  `/dashboard/` already have -- not a new trust model, but it is a new
  concrete surface that needs its own tests (bounded provider_id input,
  rate limit enforced, unknown provider returns 404 not 500).
- The Agent's mTLS trust model changes from "exactly one CA, exactly one
  client class" to "one CA plus one dynamically pushed key allowlist,
  two client classes" -- the exact increase in attack surface ADR-011 §
  "Consequences" already flagged and required tests for (unauthorized
  validator rejected, expired allowlist entry rejected).
- Until slices 2-5 land, `pallet-network-validator`'s evidence pipeline has
  no real submitter other than whatever manual/test tooling exists --
  registering as a validator (slice 1) does not yet mean a validator can
  do any scoring. This is an honest, visible gap, not a silent one: the
  daemon's `status` command should say so explicitly rather than imply
  readiness.
