# ADR-027: Harden mTLS PKI enrollment, rotation, and revocation

## Status

Accepted (by the repository owner, explicitly, relayed in-session — after reviewing a full summary
of this ADR's decisions and their reasoning, then confirming to proceed with implementation).

Originally written by Claude Code, autonomously, in response to issue #13, and held as Proposed per
the convention established by ADR-016/018/025/026/029: it decides how the Provider Agent's
cryptographic identity is issued, renewed, and revoked — a real security boundary, not a narrower
technical decision. Nothing here is implemented yet by this ADR itself; issue #13 is unblocked by
this acceptance and now carries the implementation work.

## Context

`AGENTS.md` already mandates mTLS between Control Plane and Agent, and it is real and working
(`provider-agent/crates/agent-cli/src/mtls.rs` builds a hand-rolled `rustls::ServerConfig` with a
custom `ClientCertVerifier` because tonic's public API has no hook for one). What is missing is
everything issue #13 names: the certificates in use today are development fixtures, not a PKI
lifecycle.

**What exists today, verified against source:**

- `deployments/scripts/generate-dev-certs.sh` generates one self-signed root CA (`ca.crt`/`ca.key`,
  RSA-3072, 365-day validity) and, off that root, exactly **one** shared client identity
  (`client.crt`/`client.key`, CN `provider-agent-dev`, 90-day validity) that every Agent instance
  in the local dev stack presents when calling `ControlPlaneService`, plus one shared Agent server
  identity (`agent-server.crt`/`agent-server.key`) that every Agent instance presents when serving
  `ProviderAgentService`. Neither is generated per-provider, neither is tied to the provider's own
  Ed25519 identity, and nothing rotates or revokes either independently of the other.
- `deployments/docker-compose.yml` mounts this same `./local/certs` directory read-only into both
  the `control-plane` and `provider-agent` containers (`TLS_CERT_FILE`/`TLS_KEY_FILE`/
  `TLS_CA_FILE`/`TLS_SERVER_NAME` on the Agent side calling out; `AGENT_TLS_CERT_FILE`/
  `AGENT_TLS_KEY_FILE`/`AGENT_TLS_CLIENT_CA_FILE` on the Agent's own server side;
  `AGENT_CLIENT_TLS_CERT_FILE`/`_KEY_FILE`/`_CA_FILE` on the Control Plane side calling the Agent).
  This is exactly the "development-only certificate assumptions" issue #13 asks to replace.
- The Provider Agent already has a real, durable, non-TLS identity: `agent-core::identity`'s
  `Ed25519IdentityManager` (`provider-agent/crates/agent-core/src/identity.rs`), a keypair
  generated once and persisted to a 0600 file (`write_private_key`), never rotated, never leaves
  the node. `control-plane/internal/providerjoin/service.go`'s `BeginJoin`/`CompleteJoin` already
  runs a full challenge-response ceremony against this exact key: `BeginJoin` issues a random
  32-byte nonce; `CompleteJoin` verifies `ed25519.Verify` over `"openinfra-join-v1\0" ‖ nonce`, and
  only then persists the provider and derives `provider_id = sha256(public_key)` (hex). This is a
  real, working, already-tested proof of possession this ADR reuses rather than replaces.
- The Agent's mTLS server already has a precedent for a **second, non-CA-chain trust basis**:
  `mtls.rs`'s `AllowlistClientCertVerifier` (ADR-013 §3) accepts a client certificate if it chains
  to the Control Plane's CA **or** if a raw Ed25519 public key extracted from a self-signed
  certificate (via real X.509 parsing, `x509_parser::parse_x509_certificate`) is in a live,
  heartbeat-refreshed allowlist. This is the same shape — "trust a key directly, not a CA chain,
  when a bootstrap trust problem exists" — this ADR needs for enrollment, just in the opposite
  direction (Agent calling in, not Control Plane calling out).
- Scheduling eligibility is already gated purely by `providers.status` and heartbeat freshness:
  `agentmanager.PostgresRegistry.ListActive` (`control-plane/internal/agentmanager/directory.go`)
  selects `WHERE status = $1` (`NODE_STATUS_ACTIVE`), and `Directory.ListSchedulableProviders`
  additionally drops any provider whose Redis heartbeat has expired (`ErrHeartbeatNotFresh`). A
  revocation mechanism that flips `providers.status` away from `ACTIVE` therefore removes
  scheduling eligibility **for free**, with no new mechanism — confirmed by reading this code path
  directly, not assumed.

**Checked against `AGENTS.md`/ADR-012 before designing anything:** the frozen-architecture rule
(`AGENTS.md:15`) forbids changing "a language, framework, database, or component boundary without
an accepted ADR." Standing up a separate CA service (a new network-facing component with its own
key material, its own deployment unit, its own trust relationship to both Control Plane and Agent)
would be exactly that — a new component boundary — and nothing in ADR-012 §6's gate table names a
CA component as an unblocked or reserved gate; it is not decentralization-stage work at all
(providers are still onboarding through one Control Plane, no P2P trust is being introduced). The
Control Plane already terminates and validates mTLS in both directions today (it already holds
`TLS_CLIENT_CA_FILE`/`AGENT_CLIENT_TLS_CERT_FILE` and already decides who is a valid client).
Having it also *issue* the certificates it already validates extends an existing responsibility; it
does not create a new one. **This ADR concludes "Control Plane issues certs itself" is the only
in-bounds answer without first getting a separate, unrequested ADR accepted for a new CA
component** — precisely the reasoning the task asked this ADR to make explicit, not assume.

This is Stage 0 hardening (milestone v1.0, per the issue's own milestone tag), not a
decentralization-stage change: ADR-012 §5 describes "Milestones v0.2, v0.3, v1.0, v1.1 harden
[Stage 0]; they do not decentralize it further," and §6's gate table has no entry that reads on PKI
hardening at all — checked line by line, none of ADR-017 through ADR-024 name certificates,
enrollment, or revocation. No gate needs lifting.

## Decision

### 1. CA placement and operator

The Control Plane operates a single CA. Its private key lives only inside the Control Plane's own
runtime environment — in the local dev stack, mounted the same way `server.crt`/`server.key`
already are today (`./local/certs:/run/openinfra-tls:ro`, `control-plane` service only, never
mounted into the `provider-agent` container). It is used for exactly two things: (a) the Control
Plane's own long-lived, operator-provisioned server identity (unchanged by this ADR — still
generated and rotated the way `generate-dev-certs.sh`'s `server.crt`/`server.key` are today, or by
a real external CA in a non-dev deployment), and (b) issuing short-lived Provider Agent leaf
certificates, the new work this ADR adds. The CA key never crosses a process boundary, is never
returned in any RPC response, and is never logged — cert-issuance code logs `provider_id`, serial
number, and expiry only, matching `AGENTS.md`'s blanket "never log secrets" rule.

No new component boundary is introduced (see Context). A future multi-Control-Plane deployment
(ADR-017, not yet written) may need to decide how a replicated CA works; this ADR is explicitly
Stage-0/single-Control-Plane-scoped and says so rather than pre-designing for a component that
doesn't exist yet.

### 2. Enrollment: extends `CompleteJoin`, does not add a new step

**Bootstrap trust problem.** `BeginJoin`/`CompleteJoin` are themselves mTLS RPCs
(`control_plane.proto`: "Every RPC requires mutually authenticated TLS in non-development
environments"), but a brand-new Provider Agent has no Control-Plane-issued certificate yet — it
cannot have one until enrollment completes. This is the same bootstrap problem ADR-013 §3 already
solved in the opposite direction for Network Validators, by trusting a self-signed certificate's
*raw key* rather than a CA chain, with the real trust decision deferred to something else (there:
chain membership; here: the Ed25519 challenge signature).

**Decision:** the Control Plane's mTLS listener gains a bootstrap trust class scoped to exactly
`BeginJoin`/`CompleteJoin`: it accepts any well-formed, self-signed certificate for those two RPCs
only (mirroring `AllowlistClientCertVerifier`'s existing raw-key-extraction code, same shape,
opposite direction — a Go `tls.Config.VerifyPeerCertificate` callback that special-cases these two
method names before falling through to the normal CA-chain-or-reject check every other RPC keeps).
The TLS layer grants no authorization by itself here; `CompleteJoin`'s existing `ed25519.Verify`
check over the challenge nonce is what actually authorizes anything, exactly as it does today.

**New wire fields, not a new RPC:**

- `CompleteJoinRequest` gains `tls_public_key` (raw 32-byte Ed25519) — a **freshly generated**
  keypair, distinct from the long-term identity key (see below for why), whose public half the
  Agent is asking the Control Plane to certify.
- `CompleteJoinResponse` gains `certificate_pem` (the issued leaf certificate, CA-signed, CN/SAN
  bound to `provider_id`) and `certificate_expires_at`.

**Why the binding is sound:** `CompleteJoin` only reaches the point of issuing anything after the
same `challenge_signature` verification that already gates provider registration today — the
long-term Ed25519 identity key must sign the server-issued nonce before any certificate is minted.
This is deliberately **reuse of the existing signature-verification flow**, not a new enrollment
ceremony, per the task's own framing. One honest limitation, stated rather than hidden: today's
signature covers only the nonce, not the rest of the request body (`capabilities` isn't covered
either, and this predates this ADR) — tamper protection for `tls_public_key` in transit rests on
TLS channel integrity, the same property the existing `capabilities` field already relies on. This
ADR does not change that pre-existing property; widening the signed payload to cover the whole
request is flagged as a possible future hardening, not solved here.

**Why a fresh TLS keypair, not the identity key itself:** ADR-011 §2 already decided Network
Validators reuse their chain key directly as their TLS key ("no separate validator PKI"). This ADR
makes the opposite choice for the Provider Agent, deliberately: the identity key also signs every
join and heartbeat message and is the root of the provider's on-chain-adjacent identity
(`provider_id = sha256(public_key)`); handing that same key to a TLS stack as raw session key
material exposes it to more code paths (rustls internals, more frequent handshakes, more logging
surface) for a benefit (saving one keypair generation) this ADR judges not worth the exposure
increase. A compromised leaf TLS private key must not equal a compromised provider identity.

### 3. Renewal

- **Lifetime:** 24 hours per leaf certificate. Short enough to bound the blast radius of a leaked
  leaf key to at most a day of unauthorized connectivity; long enough that renewal traffic (one
  request roughly per day per provider) stays a rounding error next to the existing ~15s heartbeat
  cadence.
- **Trigger:** the Agent attempts renewal once 50% of the certificate's lifetime has elapsed (12
  hours in), giving a 12-hour overlap window to recover from any single renewal failure before the
  certificate actually expires.
- **Overlap:** the previous certificate remains valid (on its own `NotAfter`) for the rest of its
  lifetime while the new one is valid from the moment it's issued — both are simultaneously usable
  during the overlap window, so there is never a reconnect gap from rotation itself.
- **Mechanism, not a re-run of enrollment:** a new RPC pair on `ControlPlaneService`,
  `RenewCertificate(RenewCertificateRequest) returns (RenewCertificateResponse)`, callable **only**
  over a connection currently authenticated with a still-valid, previously Control-Plane-issued
  leaf certificate — never over the bootstrap self-signed path, which is reserved for first
  enrollment. The request carries a **new** freshly generated TLS public key (leaf keys are never
  reused across renewal periods either — short-lived all the way down, not just the certificate
  wrapper) plus an Ed25519 signature, over a new domain-separated string
  (`"openinfra-cert-renew-v1\0"`) covering `new_tls_public_key ‖ current_certificate_serial ‖
  timestamp ‖ nonce`, from the long-term identity key. The nonce and timestamp give this the same
  replay-protection shape ADR-012 §4 requires of every new signed message (subject + sequence/nonce
  + deadline) — reusing `agent-core::local_state`'s existing pattern for a durable, restart-
  surviving monotonic counter (`next_heartbeat_sequence`) for a new `next_renewal_sequence`.
- **If renewal keeps failing before expiry** (Control Plane unreachable, network partition):
  bounded exponential-backoff retries, base 30s doubling to a 10-minute cap, continuing until
  either success or the current certificate's `NotAfter`. No soft grace period past `NotAfter` — a
  hard cryptographic boundary is simpler to reason about and audit than a fuzzy extension window.
  Once the certificate actually expires unrenewed, the Agent can no longer open a new mTLS
  connection to the Control Plane at all — this is indistinguishable, by design, from any other
  network partition, and is exactly the situation ADR-028 (Provider Agent disconnected mode, this
  same PR) governs. The two proposals compose: an unrenewed expired certificate is one concrete way
  a provider ends up disconnected, not a separate failure mode needing its own handling.

### 4. Revocation

- **Trigger:** a new `controlplane-admin revoke-provider <provider-id>` subcommand, mirroring the
  existing break-glass pattern ADR-016 §4 already established for `grant-role`/`issue-key`/
  `revoke-key` — becoming revoked, like becoming an operator, is not self-service.
- **Where the state lives:** reuses `providers.status` (Postgres, already the authoritative
  off-chain store for this exact column) rather than a new table or a new database — satisfies
  `AGENTS.md`'s prohibition on introducing another database directly, no ADR gate needed for that
  reason. A new enum value, `NODE_STATUS_REVOKED`, is added to `shared.proto`'s `NodeStatus` (a
  proto change, flagged in Consequences).
- **Scheduling eligibility — immediate, zero new mechanism:** `PostgresRegistry.ListActive`'s
  `WHERE status = $1` (`ACTIVE`) already excludes any provider not in that exact status. The moment
  `revoke-provider` writes `REVOKED`, the very next scheduling pass — not the next heartbeat cycle
  — stops considering that provider. This is the cleanest possible answer precisely because it
  reuses code that already exists and was already read, not designed fresh for this ADR.
- **Connectivity — bounded, not instantaneous, and the bound is stated honestly:** scheduling
  eligibility alone doesn't cut an already-open mTLS session or reject a still-valid certificate's
  next handshake. `revoke-provider` additionally writes the provider's identity into a small live
  revocation set in Redis (`openinfra:revoked:<provider_id>`), reconstructible from
  `providers.status = REVOKED` if Redis is ever flushed (a reconciliation sweep run at Control
  Plane startup and on a short period, e.g. every 30s, rebuilds it — satisfying "Redis contains
  only reconstructible state," `AGENTS.md:23`). Two enforcement points consult it:
  1. **New handshakes:** the Control Plane's `VerifyPeerCertificate` callback extracts the peer's
     bound identity from the presented leaf certificate and checks the revocation set before
     completing the handshake — a revoked provider's cert, even though cryptographically still
     valid and CA-chained, is rejected outright.
  2. **Already-open connections:** a gRPC unary interceptor on `ControlPlaneService` checks the
     same set on **every** RPC (not only `ReportHeartbeat`), keyed off the already-verified peer
     certificate's identity. Because this is a fast in-memory/Redis check on every call rather than
     something gated by the ~15s heartbeat cadence, an already-open connection's very next RPC
     after revocation is rejected — bounded by the interceptor's own lookup latency (single-digit
     milliseconds), not by "up to one heartbeat interval." This is deliberately tighter than the
     acceptance criteria's explicit "not just at next heartbeat" bar, and the bound is named
     explicitly here rather than claimed to be instantaneous, which it is not (a genuinely
     instantaneous cut would require forcibly closing the underlying TCP connection from the server
     side the instant the operator's command runs; this design does not attempt that, judging
     "rejected on the very next call, typically within the same handshake round-trip in practice
     for a hostile actor probing repeatedly" as sufficient without the added complexity of a
     connection-kill side channel into the transport layer).
- **Scope, stated explicitly:** this covers the Agent-as-`ControlPlaneService`-client direction only
  — the one direction where a revoked provider could otherwise keep talking to the network it's
  been kicked out of. The reverse direction (Control Plane dispatching `Deploy`/`Stop` to a revoked
  Agent's own server) is already cut for free once scheduling eligibility drops: the orchestrator
  simply stops addressing that provider. What happens to a revoked provider's **already-running**
  leased workloads is a lease-policy question, not a PKI question — governed by ADR-028's lease
  handling and whatever lease-termination mechanism already exists, not designed here.

### 5. Key/CA material handling

- **CA private key:** never enters a container image, never committed to Git, never logged. Lives
  only in the Control Plane's runtime filesystem/secret mount, exactly the access pattern
  `deployments/docker-compose.yml` already uses for `server.key` today (`./local/certs:...:ro`,
  `control-plane` service only).
- **Provider Agent's leaf private key:** generated locally by the Agent process itself and never
  transmitted anywhere — only its public half (the "CSR," in this design just a raw public key,
  not a full PKCS#10 CSR, matching the simplicity of the existing challenge-response wire format)
  crosses the wire. Persisted alongside `agent-core::identity`'s existing key file, same 0600
  permission convention (`write_private_key`), never logged, never committed.

### 6. Migration from `generate-dev-certs.sh`

- The script keeps generating the root CA (`ca.crt`/`ca.key`) exactly as today — the artifact whose
  shape doesn't change, just its role (from "sign three static certs once" to "stay loaded in the
  Control Plane process and sign leaf certs on demand").
- The script's `client.crt`/`client.key`/`agent-server.crt`/`agent-server.key` generation — today
  one shared, long-lived, hand-issued identity used by *every* Agent instance in the dev stack — is
  retired once enrollment/renewal are implemented. The dev flow becomes: Control Plane starts
  holding `ca.crt`+`ca.key` as an issuer; a fresh `agent-cli join` obtains its own leaf certificate
  dynamically as part of `CompleteJoin`'s response, the same code path production uses. No more
  copy-pasted shared identity across instances, in dev or anywhere else.
- `server.crt`/`server.key` (the Control Plane's own server identity, presented to Agents connecting
  in) is unaffected — unchanged generation, unchanged rotation story, out of scope for this ADR.
- **Sequencing note for the implementing PR, not a design decision this ADR needs to settle
  further:** keep the current static-cert path working behind a flag during implementation so
  `make dev-up` isn't broken mid-migration, the same incremental-slice discipline ADR-013/ADR-016
  already used.

## Consequences

- Proto changes needing the standard `AGENTS.md` consumer analysis before implementation:
  `CompleteJoinRequest.tls_public_key`, `CompleteJoinResponse.certificate_pem`/
  `certificate_expires_at`, a new `RenewCertificateRequest`/`RenewCertificateResponse` RPC pair, and
  `NodeStatus.NODE_STATUS_REVOKED`. Consumers: `agent-cli` (producer/consumer of both), the Control
  Plane's `providerjoin` service (issuer), `internal/protocolcontract` (new contract-conformance
  cases), and `agentmanager`/`orchestrator` (must treat `REVOKED` as excluded, same as any non-
  `ACTIVE` status today).
- A new `controlplane-admin revoke-provider` subcommand, needing the same operational care (who can
  run it, is it logged) ADR-016 already required of `grant-role`/`issue-key`.
- The Control Plane's gRPC server gains a custom peer-certificate verifier and a unary interceptor —
  genuinely new code paths, needing the test coverage the issue itself names: expired, revoked,
  wrong-CA, rotation-in-progress (both certs simultaneously valid during overlap), and clock-skew
  cases, plus a full-handshake integration test in the shape of `mtls.rs`'s existing
  `full_handshake_accepts_ca_chained_client`.
- `agent-core` gains persisted leaf-certificate state (its own key, the issued cert, its expiry)
  alongside the existing identity key, plus a background renewal task inside `handle_start`'s
  existing long-running process (the same process that already runs the background heartbeat loop,
  per `agent-cli/src/main.rs`).
- Redis gains one new reconstructible key class (`openinfra:revoked:*`), consistent with the
  existing "Redis is reconstructible, never authoritative" rule.
- `deployments/scripts/generate-dev-certs.sh` shrinks once implemented — one less thing to keep in
  sync by hand across every Agent instance in local dev.

## Open questions for the accepting reviewer

- **CA root key algorithm.** `generate-dev-certs.sh` currently generates an RSA-3072 root while this
  ADR's leaf certificates are Ed25519 (matching the Agent's own identity key type, and matching how
  `rcgen`/`rustls` are already exercised with `PKCS_ED25519` in `mtls.rs`'s test fixtures). This ADR
  does not decide whether the CA root itself should also move to Ed25519 — it proposes leaving the
  root as-is (only *leaf issuance* changes) as the smaller, lower-risk change, but flags this as
  genuinely unresolved rather than silently picking an answer.
- **Whether 24h/50%/30s-10min are the right numbers for a real, non-dev multi-operator deployment.**
  They are reasoned defaults (bounded blast radius, ample overlap runway, backoff shape mirrored
  from `providerjoin.Reconciler`'s already-accepted 5s→10min pattern), not measured under real
  operational load. Worth revisiting once this ships and produces real renewal-failure data.
- **Multi-Control-Plane CA replication.** Explicitly out of scope — this ADR is single-Control-Plane
  (Stage 0) scoped. ADR-017 (multi-Control-Plane and relay protocol, not yet written) will need to
  reconcile with whatever this ADR ships, likely by designing how CA key material and issuance
  authority are shared or federated across replicas.

## Verification

Checked against source before writing: `provider-agent/crates/agent-cli/src/mtls.rs` (full file —
`AllowlistClientCertVerifier`, `extract_ed25519_raw_public_key`, `build_server_config`, test
fixtures); `deployments/scripts/generate-dev-certs.sh` (full file); `deployments/docker-compose.yml`
(every `TLS_*`/`AGENT_*TLS*` environment variable and cert-mount line);
`provider-agent/crates/agent-core/src/identity.rs` (full file — `Ed25519IdentityManager`,
`write_private_key`'s 0600 permission handling); `control-plane/internal/providerjoin/service.go`
(full file — `BeginJoin`/`CompleteJoin`/`ReportHeartbeat`, the `joinDomain`/`heartbeatDomain`
domain-separation convention, `maxHeartbeatClockSkew`); `control-plane/internal/agentmanager/
directory.go` (full file — `ListActive`'s `WHERE status = $1`, `ListSchedulableProviders`'s
heartbeat-freshness filter); `protocol/proto/openinfra/controlplane/v1/control_plane.proto` (full
file — every message on `ControlPlaneService`, the "every RPC requires mTLS" doc comment);
`protocol/proto/openinfra/shared/v1/shared.proto` (`NodeStatus` enum, confirmed no `REVOKED` value
exists); `provider-agent/crates/agent-cli/src/main.rs` (`handle_start`'s background heartbeat task,
`TLS_CERT_FILE`/`AGENT_TLS_CERT_FILE`-family env var loading); `docs/adr/012-decentralization-
roadmap-and-trust-boundaries.md` (§5, §6 — confirmed no gate names a CA component or PKI hardening);
`docs/adr/013-network-validator-daemon.md` §3 step 3 (the dual-trust-basis precedent this ADR mirrors
in the opposite direction); `docs/adr/016-dashboard-rbac-and-tenant-isolation.md` §4 (the
`controlplane-admin` break-glass precedent `revoke-provider` follows); `AGENTS.md` (frozen-
architecture and prohibited-changes sections, in full).

Refs #13. Related: ADR-011 §2 (no separate Network Validator PKI — the precedent this ADR
deliberately diverges from for the Provider Agent, with reasoning stated), ADR-012 §4 (replay-
protection convention reused for renewal), ADR-013 §3 (dual-trust-basis mTLS precedent), ADR-016 §4
(break-glass admin-action precedent), ADR-028 (disconnected mode — composes with an unrenewed
expired certificate as one path into disconnection).
