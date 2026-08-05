# Protocol Guidelines

## Contract Authority

Files under `proto/` are the network source of truth. Generate Go and Rust types; do not maintain handwritten equivalents.

## Compatibility Rules

- Version packages explicitly and make field units visible in names or comments.
- Give enums an explicit `*_UNSPECIFIED = 0` value and document fields, ownership, validation, and sensitive values.
- Preserve existing field numbers and meanings. Never reuse a deleted number or name; mark both as `reserved`.
- Add fields compatibly. Treat removals, renames, type changes, cardinality changes, and RPC direction changes as breaking.
- Analyze all consumers, run Buf lint/breaking checks, regenerate Go and Rust, and update contract tests before merging.
- Never expose private keys or place authentication secrets in ordinary telemetry or events.

Generated files belong under `generated/` and must not be manually edited.
