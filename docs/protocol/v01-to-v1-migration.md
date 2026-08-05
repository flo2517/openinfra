# Protocol v01 to v1 Migration

The earlier contracts were ungenerated, unimplemented scaffolds and had no released wire consumers. This intentional pre-MVP breaking revision establishes stable package and RPC conventions.

## Changes

- Packages now use `.v1` and files follow package directories under `protocol/proto/openinfra/`.
- Join was removed from `ProviderAgentService` and added to `ControlPlaneService` as `BeginJoin` plus `CompleteJoin`.
- Heartbeats are Agent-to-Control Plane unary reports with idempotency, sequence, timestamp, capabilities, and Ed25519 signature fields.
- The session token was removed; transport authentication is mTLS.
- Services and RPC messages follow Buf naming conventions.
- Enum zero values are explicitly `UNSPECIFIED`; existing numeric enum values changed.
- Go models are generated under `protocol/generated/go`; handwritten shared models were removed.
- Rust builds generate all three packages from the canonical Proto tree.

Do not run mixed `v01` and `v1` binaries. There is no compatibility adapter because no production deployment exists. Future v1 evolution must preserve field numbers and enum meanings; removed identifiers must be reserved.
