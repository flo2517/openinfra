# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Read `AGENTS.md` first — it is the binding, machine-checked-by-humans source of the frozen
architecture, integration rules, security rules, and prohibited changes for this repo. This file
adds commands and a code-map that `AGENTS.md` doesn't cover.

## What this is

OpenInfra Network is an MVP for a decentralized provider cloud (Bittensor-inspired): independent
providers advertise CPU/RAM/storage/network resources, a Control Plane matches workloads to
providers, deploys them as Docker containers, and a Substrate chain tracks identity, leases,
reputation, and Reward Points. Three languages, one system: Rust (`provider-agent/`, `blockchain/`),
Go (`control-plane/`), Protobuf (`protocol/`) as the contract layer between them.

## Commands

Everything routes through the root `Makefile` (`make help` lists targets). Each target `cd`s into
the relevant component before invoking its native toolchain — there is no unified build tool.

```bash
make fmt              # cargo fmt --check (provider-agent, blockchain) + gofmt -l (control-plane)
make lint             # clippy -D warnings (both Rust workspaces) + go vet + buf lint
make test             # test-agent + test-control-plane + test-blockchain
make test-agent       # cd provider-agent && cargo test --workspace
make test-control-plane   # cd control-plane && go test ./...
make test-blockchain  # cd blockchain && cargo test --workspace
make proto            # buf lint + buf generate, then gofmt/vet/test the generated Go
make e2e              # tests/e2e/run.sh (not run in CI — see Known gaps below)
```

A command only counts as passing if it was actually executed — do not report a Rust/Go build or
test as green without having run it in this session.

**Single-test invocation** (there are two independent Rust workspaces — `provider-agent/` and
`blockchain/` — don't confuse them):

```bash
# Rust, provider-agent crates
cd provider-agent && cargo test -p agent-core identity::

# Rust, a single pallet
cd blockchain && cargo test -p pallet-lease

# Go, one test in one package
cd control-plane && go test ./internal/providerjoin/ -run TestJoinCompletesOnlyWithValidSignature -v
```

**Local dev stack** (from README):

```bash
cp .env.example .env
make dev-up            # builds + waits on healthchecks: postgres, redis, blockchain-node,
                        # control-plane (mTLS), provider-agent, docker-socket-proxy, docker-executor
(cd provider-agent && cargo run -p agent-cli -- init)
(set -a; . ./.env; set +a; cd provider-agent && cargo run -p agent-cli -- join)
```

- Dashboard (read-only, registered providers / heartbeats / finalized-chain progress):
  `http://127.0.0.1:8080/dashboard/`
- Chain RPC health: `curl -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"system_health","params":[]}' http://127.0.0.1:9944/`
- `make dev-down` keeps volumes; `make dev-clean` wipes postgres/redis/substrate data.
- `agent-cli` subcommands: `init`, `doctor`, `start`, `join`, `heartbeat`, `status` (the last is a
  stub — `status is not implemented`, don't rely on it).

CI (`.github/workflows/ci.yml`) runs four independent jobs — control-plane, provider-agent,
protocol, blockchain — each with its own fmt/lint/test steps matching the `make` targets above.
The protocol job also verifies `git diff --exit-code -- protocol/generated`, i.e. generated
bindings must be committed and in sync with the `.proto` sources.

## Architecture

### Process boundaries and how a request crosses them

```
User -> Control Plane (Go) -- gRPC (protocol/proto) --> Provider Agent (Rust) -> Docker
              |                                                  |
              +-> PostgreSQL (source of truth off-chain)         +-> local Ed25519 identity,
              +-> Redis (heartbeats/cache/locks, reconstructible)   local state (never touches chain)
              +-> Blockchain Bridge -- JSON-RPC --> Substrate runtime (blockchain/)
```

The Provider Agent **never** talks to the chain directly in the MVP — all on-chain reads/writes go
through the Control Plane's `blockchainbridge` package. `protocol/proto/` is the single source of
truth for every cross-process message and RPC; generated Go lives in `protocol/generated/go`,
generated Rust bindings are produced at build time in `provider-agent`. Never hand-declare a struct
that duplicates a proto message — regenerate via `make proto` instead.

### Reference flow (build/reason about this before anything more ambitious)

```
Provider Agent starts -> loads/creates Ed25519 identity (agent-core::identity)
  -> BeginJoin/CompleteJoin against Control Plane (internal/providerjoin, signature-verified)
  -> provider persisted in PostgreSQL, heartbeats cached in Redis
  -> heartbeat cadence (every 15s) flips provider to ACTIVE
  -> user submits workload -> internal/scheduler ranks providers
  -> internal/orchestrator drives a Lease + DeployRequest -> Agent's agent-executor runs the
     container via bollard -> real container_id / RUNNING only reported after the Agent confirms
  -> availability proofs / metrics feed the availability, reputation and rewards pallets on-chain
```

### Where things live

**`provider-agent/`** (Cargo workspace, 5 crates): `agent-core` (Ed25519 identity, local state,
errors), `agent-api` (gRPC server implementing `ProviderAgentService`), `agent-executor` (bollard
Docker execution), `agent-inventory` (sysinfo-based hardware inventory), `agent-cli` (the binary;
`init`/`join`/`heartbeat`/`start` are real, `status` is not implemented).

**`control-plane/`** (Go module `github.com/openinfra/network`): three binaries under `cmd/`
(`controlplane`, `scheduler`, `provideragent`); logic under `internal/`:
- `providerjoin` — Join/heartbeat handlers, signature verification (the most test-covered package)
- `agentmanager` — tracks known agents/connections
- `blockchainbridge` — JSON-RPC client into the Substrate node (real, non-trivial: ~950 LOC)
- `scheduler` — provider ranking/scoring; currently thin (~85 LOC), not yet the full
  reputation-vector scheduler described in the architecture docs — treat as a known gap, not a
  reference implementation
- `orchestrator` — drives workload deploy lifecycle against the Agent
- `workloadapi` — user-facing workload submission/status API
- `wireguard` — lease-gated overlay networking (added post-MVP-baseline)
- `dashboard` — the read-only ops dashboard served at `/dashboard/`
- `protocolcontract` — contract-conformance tests against the generated proto types, not a
  runtime package
- `migrations/` — 7 sequential SQL files (Postgres is authoritative off-chain state)

**`blockchain/`** (Cargo workspace: `node`, `runtime`, 6 pallets): `provider-registry`,
`resource-market`, `lease`, `reputation`, `rewards`, `availability` — all six exist with real
`src/lib.rs` + `src/tests.rs`, not scaffolds. Local dev chain uses manual sealing / a local Aura
GRANDPA testnet with an endowed sudo bridge account — development-only, not production consensus.
Runtime rules from `AGENTS.md` apply strictly here: no floats, no unchecked arithmetic, no
network/std access, explicit origin checks on every extrinsic.

**`protocol/`**: `.proto` sources under `proto/openinfra/{shared,agent,controlplane}/v1/`
(`shared.proto` defines the cross-cutting types — NodeIdentity, ResourceCapability,
ReputationVector, WorkloadDefinition, Lease, EventEnvelope; `agent.proto` defines
`ProviderAgentService`; `control_plane.proto` defines `ControlPlaneService`), plus `buf` config for
lint/breaking-change checks and generation.

**`tests/`**: a single `tests/e2e/run.sh` entrypoint (own `AGENTS.md` inside). Not currently wired
into CI — CI only gates the four per-component jobs, so e2e regressions won't be caught
automatically.

**`docs/adr/`**: numbered ADRs are the record of accepted architecture decisions (language choices,
Postgres/Redis split, on-chain/off-chain boundary, WireGuard, the local testnet, etc.). Any
structural change (language, framework, database, component boundary) needs a new ADR here before
implementation, per `AGENTS.md`.

### Known gaps worth knowing up front

- `agent-cli status` is unimplemented (logs an error, does nothing).
- `control-plane/internal/scheduler` is a minimal scorer, not the full reputation-vector scheduler
  the architecture docs describe.
- `tests/e2e/run.sh` exists and is invoked via `make e2e`, but is not part of the CI workflow.
- Treat `architecture.md` / `architecture_review.md` as the aspirational/vision layer, not proof of
  what's implemented — verify against the code above before relying on a claim from those files.
