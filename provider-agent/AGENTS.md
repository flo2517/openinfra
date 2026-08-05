# Provider Agent Guidelines

## Scope

This Rust workspace owns Ed25519 identity, gRPC, hardware inventory, Docker execution, Prometheus metrics, local proofs, minimal local state, and temporary disconnected operation. It communicates only with the Control Plane; direct blockchain access is forbidden in the MVP.

## Implementation Rules

- Use traits for identity, executor, inventory, persistence, and transport backends. Keep errors typed and propagated; do not use `unwrap()` or `expect()` in production paths.
- Validate all RPC input and use structured `tracing` fields. Never expose or log private-key material, credentials, or session tokens.
- Return deployment success only after Docker confirms the container state. Persist `workload_id -> container_id`; never locate or stop containers through substring matching.
- Enforce image policy, CPU and memory quotas, PID limits, `no-new-privileges`, and a configured maximum workload count. Prefer non-root, capability-dropped, read-only containers where compatible.
- Write keys atomically with owner-only permissions. Require authenticated mTLS for non-loopback listeners.

## Validation

Run from this directory:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Add unit tests beside crates and integration tests under `tests/`. Cover error, timeout, restart, and Docker-confirmation paths.
