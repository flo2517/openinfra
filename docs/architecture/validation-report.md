# Validation Report — 2026-08-05

## Successful Checks

- `cd provider-agent && cargo fmt --all -- --check`
- `cd provider-agent && cargo check --workspace --all-targets --offline`
- `cd provider-agent && cargo clippy --workspace --all-targets --offline -- -D warnings`
- `cd provider-agent && cargo test --workspace`: 5 passed, 0 failed; identity, persistent heartbeat sequence, inventory, and plaintext transport policy. Generated Unix key files use owner-only mode and exclusive creation.
- `cd control-plane && gofmt -w . && go vet ./... && go test ./...`: all packages compile and all tests pass.
- Buf lint and generation succeed for the three v1 packages under `protocol/proto/openinfra/`; the generated Go module passes `go vet ./...` and `go test ./...`.
- Contract tests verify RPC direction, explicit enum zero values, and deterministic heartbeat signing serialization.
- `make test-control-plane`: all packages compile; 3 protocol contract tests pass.
- Provider Join tests cover valid completion, idempotent retry, invalid signatures, signed heartbeat acceptance, and sequence replay rejection.
- Agent Manager tests verify that registration alone cannot authorize deployment and that scheduler visibility requires both an `ACTIVE` PostgreSQL row and a fresh, identity-matching Redis heartbeat.
- `tests/e2e/run.sh` passed against the real Compose stack: isolated Agent initialization, mTLS Join, signed heartbeat sequence `1`, positive Redis TTL, and automatic PostgreSQL/Redis cleanup.
- `docker compose config --quiet` succeeds; PostgreSQL, Redis, and Control Plane report healthy.
- `cd blockchain && cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` succeed for the six FRAME pallets and assembled development runtime.
- `cd blockchain && cargo check --workspace --no-default-features` confirms the runtime and pallets compile in `no_std` mode.
- `cd blockchain && cargo check -p openinfra-runtime` builds the native runtime and its embedded `wasm32v1-none` artifact.
- `cd blockchain && cargo test -p openinfra-runtime`: 4 passed, 0 failed; development genesis, runtime integrity, and the bridge call-index golden vector are validated.
- The digest-pinned `openinfra-blockchain-node` release image builds successfully. Its non-root, read-only container is healthy, initializes genesis, persists RocksDB in a named volume, and produces finalized manual-seal blocks every three seconds.
- JSON-RPC `system_health` returned healthy and `chain_getHeader` returned block `#6` during live validation on `127.0.0.1:9944`.
- The Go Blockchain Bridge JSON-RPC client validates endpoints, propagates context deadlines, returns typed RPC errors, reads chain health and parses hexadecimal block numbers. Its four tests pass.
- The rebuilt Control Plane connected to the Compose node at startup and logged a verified head at block `#251`; all four Compose services remained healthy.
- The Provider Join and signed Heartbeat E2E regression passed after enabling the live chain dependency.
- ADR-009 is accepted. `provider-registry::register_provider_for` preserves existing call indices and rejects unauthorized origins, duplicate accounts, duplicate keys, and zero keys; six pallet tests pass.
- Runtime `spec_version = 2` includes `pallet-balances` so the development bridge account owns nonce storage. Its Ed25519 private key remains outside the image and repository; only its public account is endowed at genesis.
- The Go bridge encodes this runtime's transaction extensions, submits `sudo(register_provider_for)` followed by the verified and active transitions, and confirms the provider record at a finalized head. The local-node integration test passes in approximately three seconds.
- PostgreSQL migrations now run transactionally at Control Plane startup. Join persists `PENDING` plus a chain-registration record, heartbeat rejects non-active providers, and PostgreSQL becomes `ACTIVE` only after finalized chain storage confirms the identity and status.
- The final `tests/e2e/run.sh` run passed with on-chain registration, PostgreSQL activation, mTLS Agent response, signed heartbeat, positive Redis TTL, and clean off-chain teardown.
- The Provider Agent Docker executor validates UUID identities and bounded CPU/RAM, atomically enforces maximum active workloads, persists exact workload-to-container records in sled, and confirms running/stopped state through Docker inspection. It never searches containers by substring.
- Mandatory Docker controls are applied: `NanoCpus`, memory with no additional swap, PID limit, `no-new-privileges`, `cap-drop=ALL`, init, and ownership labels. The gated real-daemon test verified these values against Docker and cleaned up its container.
- `cd provider-agent && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` passes: 11 tests, including idempotence, request conflict, quota capacity, exact stop/status resolution, sled reopen, and restart recovery.
- Local secret-pattern scan found no committed credential or private-key material. Git history could not be scanned because `.git` is empty.

## Failed or Blocked Checks

- Generated benchmark weights do not exist yet. Manual seal and sudo are development-only and are not production consensus or governance mechanisms.
- The host `cargo check -p openinfra-node` is blocked by a missing `libclang-14.so.13`; the digest-pinned Docker build succeeds because its build stage includes Clang/LLVM.
- Reconciliation is retry-driven: a repeated idempotent `CompleteJoin` repairs a crash after on-chain finality, but no autonomous PostgreSQL outbox worker currently scans stranded `PENDING` registrations.
- Docker recovery relies on persisted mappings. Automatic adoption or quarantine of a labeled orphan created during the narrow create-before-persist crash window remains to be implemented.

Go 1.25.1, Docker 29.1.3, and Compose 2.40.3 are available. Digest-pinned PostgreSQL 17.6, Redis 8.2.1, the non-root read-only Control Plane, and the non-root Substrate node pass their healthchecks. A real Rust Agent completed Join over mTLS, persisted its provider ID locally, sent a signed heartbeat, and produced a Redis liveness record with a 45-second TTL. PostgreSQL retained the authoritative 32-byte Ed25519 identity and registration.

## Remaining Build Risks

The Control Plane consumes generated Protobuf bindings and implements PostgreSQL-backed Join, Redis-backed Heartbeat, a scheduler-facing availability projection, and signed/finalized Provider Registry transactions. Redis loss removes only reconstructible liveness state and makes providers temporarily unschedulable. The blockchain has a FRAME 48 workspace, six bounded/tested pallets, a deterministic WASM runtime, a development chain spec, and a live local node. Production benchmark weights, autonomous bridge reconciliation, authoritative cross-pallet reward inputs, and production consensus/governance remain. Provider Agent compilation and the secured Docker executor are green, but the Control Plane does not yet dispatch a lease-authorized workload to the Agent and several RPCs remain incomplete.

The Control Plane now also serves a read-only dashboard on the loopback-published port `8080`. Its overview is built from PostgreSQL provider state, Redis heartbeat TTLs, and finalized Substrate headers; dependency failures produce explicit partial/unknown data rather than false offline status. Workloads are intentionally absent until their PostgreSQL state machine and finalized lease gate exist.

Provider Join now accepts an additive, HTTPS-only Agent endpoint and persists it with the signed Join idempotency payload. The Agent serves gRPC with mandatory mutual TLS outside explicit loopback development mode and emits continuous signed heartbeats while serving. A real Control Plane client successfully connected through mTLS and rejected identity unless the remote `node_id`, Ed25519 public key, and PostgreSQL provider record all matched.

The versioned workload API and PostgreSQL state ledger are operational. A real mTLS `SubmitWorkload` followed by `GetWorkload` returned the same durable UUID in `REQUESTED`; direct database inspection confirmed that provider, lease, and container remained unset. Requests require bounded resources and an immutable digest-pinned OCI image. Idempotent retries are tested, including payload-conflict rejection, and the dashboard reads workloads from PostgreSQL.

The internal Control Plane worker now advances persisted states through scheduling, finalized lease authorization, and Agent dispatch. Against the live local node it created lease `1`, verified the complete `Active` record at a finalized head, and only then called the authenticated Agent. PostgreSQL reached `RUNNING` after `GetWorkloadStatus` confirmed the exact container. Docker inspection confirmed running state, 1 CPU, 256 MiB memory, 128 PIDs, `no-new-privileges`, and the exact on-chain lease label.
