# Blockchain Workspace Migration

## Scope

This additive migration turns the six non-buildable pallet sketches into independent FRAME crates. The historical files under `runtime/src/pallets/` remain unchanged and are excluded from the workspace until the replacement crates and assembled runtime are validated.

## Mapping

| Historical sketch | Compilable crate |
| --- | --- |
| `runtime/src/pallets/provider_registry/` | `pallets/provider-registry/` |
| `runtime/src/pallets/resource_market/` | `pallets/resource-market/` |
| `runtime/src/pallets/lease/` | `pallets/lease/` |
| `runtime/src/pallets/reputation/` | `pallets/reputation/` |
| `runtime/src/pallets/rewards/` | `pallets/rewards/` |
| `runtime/src/pallets/availability/` | `pallets/availability/` |

## Safety and Rollback

No deployed storage layout exists. Until Git metadata is restored, rollback is additive: remove the new crate from the workspace and continue to retain the historical sketch. After any runtime deployment, pallet `StorageVersion` and explicit runtime migrations become mandatory; binary rollback alone is forbidden.

The first workspace milestone excludes a consensus node, token economics, staking, detailed metrics, and direct Provider Agent access. Sensitive state changes use configurable runtime origins intended for the Control Plane blockchain bridge or validator governance.
