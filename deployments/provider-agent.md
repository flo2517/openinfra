# Provider Agent local service

The local Compose stack runs the Provider Agent as a near-unprivileged service: `cap_drop: ALL` plus one capability added back, `CAP_NET_ADMIN` (see "Host network privilege" below). `make dev-up` creates development-only certificates, then Compose builds the digest-pinned image. On its first start the entrypoint creates a mode `0600` Ed25519 seed and `config.yaml` under `deployments/local/agent/`, joins the Control Plane over mTLS, and starts signed heartbeats. The directory persists the identity, assigned provider ID, heartbeat sequence, and exact workload-to-container mappings across restarts.

The Agent listens on `127.0.0.1:50052` at the host boundary and advertises `https://provider-agent:50052` inside the Compose network. It starts only after the Control Plane and Docker proxy are healthy. Its healthcheck verifies persistent initialization and the local gRPC listener; application RPCs remain protected by mandatory mTLS.

## Host network privilege

ADR-025 §3 gives the Agent process `CAP_NET_ADMIN` (`cap_add: [NET_ADMIN]` in `docker-compose.yml`, added back after `cap_drop: ALL`) so it can run `tc qdisc replace ... tbf` against the host side of a workload's veth pair, enforcing that workload's reserved egress rate as a fourth quota alongside the CPU/memory/PID limits Docker's own `HostConfig` already applies. This is a standing capability increase for the Agent's own process, explicitly signed off (see the ADR's Status line) rather than self-accepted, because it is new privilege over host networking, not just the Docker socket access the Agent already had via the proxy. It does **not** extend to the workload containers the Agent creates: their own `HostConfig` keeps `cap_drop: ALL` / `no-new-privileges` independently, applied by `agent-executor` per container, unaffected by this Compose-level grant to the Agent's own process.

## Docker boundary

The Agent does **not** mount `/var/run/docker.sock`. A dedicated, digest-pinned socket proxy exposes only Docker container, image, info, version, ping, and required `POST` endpoints on the internal `docker-executor` network. Only the Agent joins that network; the Control Plane and other services cannot reach the proxy. The proxy alone mounts the socket. This reduces accidental API exposure but is not a complete authorization boundary: Docker container creation can still imply host-level impact, and access to the Docker socket remains root-equivalent. The proxy also needs a writable container layer to render its HAProxy configuration at boot. Do not expose port `2375`, reuse this development configuration on an untrusted host, or attach unrelated services to `docker-executor`.

Workloads retain Agent-enforced CPU, memory, PID, maximum-count, dropped-capability, and `no-new-privileges` controls. Images must already exist locally and be referenced by digest.

## Operations

```bash
make dev-up
docker compose --env-file .env -f deployments/docker-compose.yml ps provider-agent
docker compose --env-file .env -f deployments/docker-compose.yml logs provider-agent
make dev-down       # preserves local Agent identity/state
make dev-clean      # removes named volumes; deployments/local remains explicit local state
```

To deliberately reset only the development Agent identity, stop the stack and remove `deployments/local/agent/`. This is destructive and registers a new on-chain provider on the next start. Never commit that directory or the generated certificates.

## Multiple instances (`multi-node` profile)

`COMPOSE_PROFILES=multi-node make dev-up` starts two more Provider Agents, `provider-agent-2` and `provider-agent-3`, alongside the default `provider-agent` -- see the README's "Multi-provider, multi-validator local network" section for why (mainly: giving `networkvalidator`'s committee more than one provider to actually challenge, and the scheduler more than one candidate to rank). Each replica is an exact copy of this service's shape -- same security posture, same `docker-socket-proxy` dependency, same digest-pinned image -- differing only in its advertised endpoint (`https://provider-agent-2:50052`/`https://provider-agent-3:50052`), host port (`PROVIDER_AGENT_2_PORT`/`PROVIDER_AGENT_3_PORT`, defaulting to `50053`/`50054`), and state directory (`deployments/local/agent-2`/`deployments/local/agent-3`).

All instances share the one `docker-socket-proxy` from this document's "Docker boundary" section above: they all ultimately reach the same underlying host Docker daemon, distinguished only by container name/labels, not by any per-provider isolation. This is a deliberate simplification for local dev's actual purpose (observable multi-provider scheduling and multi-validator behavior), not a claim of real inter-provider isolation -- do not read multiple provider-agent instances as a security boundary between them. They also share the one agent-server certificate (`deployments/scripts/generate-dev-certs.sh` puts every instance's hostname in its SAN list), since the Control Plane's outbound TLS verification checks the dialed hostname against whichever certificate the Agent presents, not a per-instance identity.

To add a fourth instance, copy one of `provider-agent-2`/`provider-agent-3`'s blocks in `deployments/docker-compose.yml`, give it a new hostname/port/state directory, and add that hostname to the SAN list `generate-dev-certs.sh` builds for `agent-server.crt`.
