# Blockchain Guidelines

## Scope

This Rust/Substrate component owns the runtime, six MVP pallets, extrinsics, storage, events, errors, weights, benchmarks, migrations, and runtime tests.

## Runtime Rules

- Runtime execution must be deterministic: no floating point, networking, clocks, filesystem, Docker, orchestration, or other external system access.
- Use checked/saturating integer arithmetic with explicit units and bounds. Bound stored collections and account for encoded size.
- Enforce authorized origins for validator/control operations. Validate every state transition, identifier uniqueness, provider relationship, and input range.
- Derive weights from benchmarks; do not ship placeholder constants. Test storage, events, errors, authorization, overflow boundaries, and upgrades.
- Store consensus-critical summaries only, never detailed metrics, logs, secrets, or real-time operational state.
- Keep blockchain validators distinct from reputation validators where the design requires separate trust roles.

## Validation

Run from this directory once a Cargo workspace is present:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
