# Provider Agent local service

The local Compose stack runs the Provider Agent as an unprivileged service. `make dev-up` creates development-only certificates, then Compose builds the digest-pinned image. On its first start the entrypoint creates a mode `0600` Ed25519 seed and `config.yaml` under `deployments/local/agent/`, joins the Control Plane over mTLS, and starts signed heartbeats. The directory persists the identity, assigned provider ID, heartbeat sequence, and exact workload-to-container mappings across restarts.

The Agent listens on `127.0.0.1:50052` at the host boundary and advertises `https://provider-agent:50052` inside the Compose network. It starts only after the Control Plane and Docker proxy are healthy. Its healthcheck verifies persistent initialization and the local gRPC listener; application RPCs remain protected by mandatory mTLS.

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
