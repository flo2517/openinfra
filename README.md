# OpenInfra Network

OpenInfra Network is an early MVP prototype for a decentralized provider cloud. Independent providers will advertise resources, receive leased workloads, report availability, and earn reputation and Reward Points.

## Status

The local Provider Join, signed heartbeat, finalized lease, and first workload flow are runnable end to end. The Compose stack includes PostgreSQL, Redis, the mTLS Control Plane with its internal durable worker, a read-only operations dashboard, and a development-only Substrate node. A workload becomes `RUNNING` only after an exact `Active` lease is visible at a finalized head and the Provider Agent confirms the Docker container is running.

## Architecture

```text
User -> Control Plane (Go) -> Provider Agent (Rust) -> Docker
              |
              +-> PostgreSQL / Redis
              +-> Blockchain Bridge -> Substrate runtime
```

Protobuf contracts in `protocol/proto/` are the interface source of truth. The Provider Agent does not communicate directly with the blockchain in the MVP.

## Repository Layout

- `provider-agent/`: Rust workspace for identity, inventory, gRPC, and Docker.
- `control-plane/`: Go orchestration, scheduling, persistence, and chain bridge.
- `blockchain/`: Substrate node, WASM runtime, and six MVP pallets.
- `protocol/`: Protobuf definitions and generation configuration.
- `deployments/`: reproducible local Compose environment.
- `tests/`: cross-component integration and E2E suites.
- `docs/`: architecture, specifications, ADRs, and audit records.

## Prerequisites

Rust/Cargo, Go, Docker with Compose, GNU Make, `protoc`, Clang/LLVM, CMake, and Buf are expected. The blockchain Docker build installs its native build dependencies and pins the Rust and Debian base images by digest.

## Development

Run `make help` for commands. `make test-agent`, `make test-control-plane`, and `make test-blockchain` validate each native toolchain. `make dev-up` builds and waits for all local service healthchecks.

### Provider Join development flow

Copy the safe local environment, start PostgreSQL, Redis, and the mTLS Control Plane, then initialize and join the Agent:

```bash
cp .env.example .env
make dev-up
(cd provider-agent && cargo run -p agent-cli -- init)
(set -a; . ./.env; set +a; cd provider-agent && cargo run -p agent-cli -- join)
```

For a locally reachable Agent server, set `agent.listen_address` to `0.0.0.0:50052` and `agent.advertised_endpoint` to `https://host.docker.internal:50052`, then run `agent-cli start` with `AGENT_TLS_CERT_FILE`, `AGENT_TLS_KEY_FILE`, and `AGENT_TLS_CLIENT_CA_FILE`. The same process sends signed heartbeats every 15 seconds. The development certificate script creates a dedicated Agent server certificate; plaintext serving is restricted to explicit `--dev` loopback mode.

The Control Plane applies versioned PostgreSQL migrations at every startup. `make dev-up` also generates a local Ed25519 bridge identity: its private key is mounted only into the Control Plane, while the public account is endowed and configured as sudo at development genesis. The local blockchain RPC is available at `http://127.0.0.1:9944`; verify it with `curl -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]}' http://127.0.0.1:9944/`. `make dev-down` preserves named volumes, while `make dev-clean` removes PostgreSQL, Redis, and Substrate data. Development keys and certificates must never be reused in production.

### Operations dashboard

Open `http://127.0.0.1:8080/dashboard/` after `make dev-up`. The dashboard polls a same-origin, read-only endpoint and reports registered providers, fresh heartbeats, available CPU/RAM, and finalized-chain progress. PostgreSQL status and Redis liveness are deliberately shown separately. The local Compose port is bound to loopback; non-local exposure requires a separate authenticated TLS deployment.

### Multi-provider, multi-validator local network

By default `make dev-up` runs one Provider Agent and one Network Validator (`cmd/networkvalidator`, ADR-011/013's continuous challenge loop). `deployments/scripts/generate-dev-certs.sh` always generates the certificates and Ed25519 signing keys for two more of each, and `deployments/scripts/bootstrap-network-validators.sh` (run automatically at the end of `make dev-up`) funds and registers whichever Network Validators are actually running from the Control Plane's own endowed bridge account -- so scaling up costs one environment variable, not a re-run of key generation:

```bash
COMPOSE_PROFILES=multi-node make dev-up
```

This starts `provider-agent-2`/`provider-agent-3` (host ports `50053`/`50054` by default, override with `PROVIDER_AGENT_2_PORT`/`PROVIDER_AGENT_3_PORT`) and `networkvalidator-2`/`networkvalidator-3` alongside the default instances -- three providers to schedule across, and three validators, which matters because `pallet-network-validator`'s `MinQuorum` is 3 (`blockchain/runtime/src/lib.rs`): a round cannot actually *close* into a reputation update with fewer than three active validators submitting evidence, no matter how many are registered. The default single-validator stack can register, go `ACTIVE`, and submit evidence, but will never see a round close on its own.

All provider instances share the one `docker-socket-proxy` and the one agent-server certificate (its SAN already covers every instance's hostname) -- local dev's purpose here is observable multi-provider scheduling and multi-validator committee behavior, not real resource or trust isolation between simulated providers, which would need per-provider Docker isolation this MVP does not have regardless of instance count. See `deployments/provider-agent.md` and `deployments/network-validator.md` for the full trust-boundary notes, including how to add a fourth or later instance by extending the pattern in `deployments/docker-compose.yml` and the `for validator in ...` / SAN list in `generate-dev-certs.sh`.

`COMPOSE_PROFILES` is read directly by the `docker compose` CLI, so no Makefile flag is needed; pass the same `COMPOSE_PROFILES=multi-node` prefix to `make dev-down`/`make dev-clean` too, so they tear down the profile's extra services instead of leaving them running. Re-running `make dev-up` (with or without the profile) is safe: certificate/key generation and validator registration are both idempotent.

## MVP Limits

The blockchain node uses deterministic three-second manual sealing and a sudo bridge account for local development only; neither is production governance or consensus. Provider Join recovery currently occurs when the Agent retries `CompleteJoin`; an autonomous outbox reconciler remains future hardening. The MVP targets Docker workloads, CPU/RAM/storage inventory, Provider Join, heartbeats, leases, availability, reputation, and Reward Points. Kubernetes, direct Agent-to-chain calls, GPU scheduling, token economics, and production-grade decentralization are out of scope unless approved by ADR. WireGuard is scheduled after lease-gated workload execution.

### Agent trust model: `CAP_NET_ADMIN`

The Provider Agent process runs with `cap_drop: ALL` plus one capability added back, `CAP_NET_ADMIN` (ADR-025 §3), so it can enforce each workload's reserved egress bandwidth as a host-side `tc` rule against the workload's veth pair -- Docker's own `HostConfig` has no bandwidth-limit field, so this is the only way to actually throttle a workload's declared reservation rather than merely book-keep it. This is a real, standing privilege increase for the Agent's own process (explicitly signed off, not self-accepted, per the ADR), separate from and in addition to the Agent's existing Docker-socket access via `docker-socket-proxy`. It does not touch the workload containers themselves, which keep their own independent `cap_drop: ALL` / `no-new-privileges` posture. See `deployments/provider-agent.md` for the full boundary.
