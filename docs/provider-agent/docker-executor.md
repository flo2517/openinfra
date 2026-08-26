# Docker Executor

The Provider Agent is the only component allowed to operate Docker. A deployment is acknowledged only after Docker inspection reports the exact container as running.

## Local Policy

`config.yaml` contains an `executor` section. Defaults limit the Agent to eight concurrent workloads, eight CPU cores and 16 GiB per workload, with 128 PIDs per container. Every request must include UUID workload and lease identifiers plus positive CPU and memory limits within this policy.

```yaml
executor:
  state_path: .openinfra-state
  max_workloads: 8
  max_cpu_cores: 8.0
  max_memory_mb: 16384
  pids_limit: 128
```

Docker receives `NanoCpus`, memory and equal memory-swap limits, the PID limit, `no-new-privileges`, `cap-drop=ALL`, an init process, and exact OpenInfra ownership labels. Image references containing whitespace or a URL scheme are rejected.

If the image isn't already present locally, `create()` pulls it once (bounded by a 3-minute timeout) on the first `404` and retries `create()` exactly once -- issue #154, confirmed live: a workload with a valid, correctly digest-pinned image reference got stuck retrying forever because nothing ever pulled it. A second `404` after a successful pull, or a pull failure/timeout, is surfaced as-is and not retried again here.

`cap-drop=ALL` + `no-new-privileges` means any image whose entrypoint needs root-level filesystem setup on first boot (the official `postgres`, `mysql`, `mongo` images all `chown`/`chmod` their data directory before dropping privileges) will fail to start under this policy -- confirmed live with `postgres`. Use an image built to run as its final non-root user from the start (e.g. Bitnami's variants), or one with no such setup step (e.g. `registry.k8s.io/pause`), for anything beyond a quick platform smoke test.

## Persistence and Recovery

Sled stores a versioned workload record containing the request fingerprint, phase, and exact `container_id`. A repeated deployment with the same fingerprint returns the existing running container; a different payload for the same workload is rejected. Stop and status operations resolve only this persisted ID and never search by name or substring.

At startup, the Agent inspects every persisted container. Running containers return to `Running`; unavailable containers become `Lost`; incomplete records without a container become `Failed`. A retry can resume a known created container without creating a duplicate. Label-based orphan adoption after a crash between Docker creation and persistence is not implemented yet.

## Validation

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
OPENINFRA_TEST_DOCKER_IMAGE=<local-image> cargo test -p agent-executor docker_integration_applies_mandatory_controls
OPENINFRA_TEST_DOCKER_PULL_IMAGE=<not-yet-pulled-image> cargo test -p agent-executor docker_integration_pulls_a_missing_image_before_create
OPENINFRA_TEST_DOCKER_NETWORK_TOOLS_IMAGE=busybox:1.36 cargo test -p agent-executor docker_integration_isolates_workload_containers_from_each_other
OPENINFRA_TEST_DOCKER_IMAGE=<local-image> cargo test -p agent-executor docker_integration_veth_resolution_survives_the_isolated_network
```

## Workload Network Isolation

Every workload container is created with `HostConfig.NetworkMode` set to a dedicated
`openinfra-workloads` bridge network instead of joining Docker's implicit default bridge --
`BollardEngine::create` ensures this network exists (idempotently, creating it with
`com.docker.network.bridge.enable_icc=false` on first use) before every genuinely new container.
Two workload containers on this network -- which may belong to two unrelated tenants -- can each
still reach the outside world (an ordinary NAT'd bridge, not `internal: true`), but Docker refuses
to forward traffic *between* them, closing the cross-tenant reachability gap the default bridge
otherwise leaves open (issue #174).

This is orthogonal to ADR-010's WireGuard-attach path: that backend resolves a workload's veth by
matching its container PID's `eth0` `iflink` against a host-side interface (`bandwidth.rs`'s own
`resolve_veth_name`, also used by ADR-025's `tc` rate-limit enforcement) -- a mechanism that
operates on the container's network *namespace* directly and has no dependency on which Docker
bridge that namespace's `eth0` happens to be attached to.

`docker-socket-proxy` (`deployments/docker-compose.yml`) needs its `NETWORKS` allow-flag set for
the Agent to create/inspect this network through the proxy; `CONTAINERS`/`POST` alone are not
enough (each resource category is an independent allow-list in tecnativa's proxy).

For `OPENINFRA_TEST_DOCKER_IMAGE` above: use an image whose *own default command* keeps running
(e.g. `registry.k8s.io/pause`) for `docker_integration_applies_mandatory_controls` and
`docker_integration_veth_resolution_survives_the_isolated_network`, which go through the real
`deploy()` path and therefore never override it. `docker_integration_isolates_workload_containers_
from_each_other` is different: it sets an explicit `Cmd` on two disposable probe containers via raw
bollard (not through `deploy()`), so it instead needs an image with BusyBox's `nc` applet, via its
own `OPENINFRA_TEST_DOCKER_NETWORK_TOOLS_IMAGE` var -- one image cannot satisfy both requirements at
once.
