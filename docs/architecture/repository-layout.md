# Repository Layout Decision

The repository uses component-first boundaries: `provider-agent/`, `control-plane/`, `blockchain/`, `protocol/`, `deployments/`, and `tests/`. This removes ambiguous root-level implementation folders and gives each component a local contributor contract.

Migration mapping:

| Previous path | Current path |
| --- | --- |
| `openinfra-agent/` | `provider-agent/` |
| `cmd/` | `control-plane/cmd/` |
| `internal/` | `control-plane/internal/` |
| `runtime/` | `blockchain/runtime/` |
| `proto/shared.proto` | `protocol/proto/openinfra/shared/v1/shared.proto` |
| `openinfra-agent/proto/agent.proto` | `protocol/proto/openinfra/agent/v1/agent.proto` |

Documentation was not broadly moved because existing specifications contain conflicting historical assumptions and few path references. The two original ADRs were retained as `legacy-*`; current accepted choices use ADR-001 through ADR-008.

The checkout contained an empty `.git` directory, so Git-aware renames and history verification were impossible. Every move was one-to-one, with no source deletion or content merge. Rollback consists of reversing this table and restoring the former Rust Proto build path.
