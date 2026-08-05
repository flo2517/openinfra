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

## Persistence and Recovery

Sled stores a versioned workload record containing the request fingerprint, phase, and exact `container_id`. A repeated deployment with the same fingerprint returns the existing running container; a different payload for the same workload is rejected. Stop and status operations resolve only this persisted ID and never search by name or substring.

At startup, the Agent inspects every persisted container. Running containers return to `Running`; unavailable containers become `Lost`; incomplete records without a container become `Failed`. A retry can resume a known created container without creating a duplicate. Label-based orphan adoption after a crash between Docker creation and persistence is not implemented yet.

## Validation

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
OPENINFRA_TEST_DOCKER_IMAGE=<local-image> cargo test -p agent-executor docker_integration_applies_mandatory_controls
```
