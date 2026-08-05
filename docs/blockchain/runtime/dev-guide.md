# Developer Guide - Blockchain Runtime v0.1

## 1. Architecture Overview
The runtime is composed of 6 independent pallets. Communication is handled via:
1. **Events**: For asynchronous notifications (e.g., `LeaseCreated`).
2. **Interfaces**: Logic defined in `blockchain/runtime/src/interfaces.rs`.

## 2. Pallet Matrix

| Pallet | Primary Extrinsic | Key Storage | Primary Event |
| :--- | :--- | :--- | :--- |
| `provider-registry` | `register_provider` | `Providers` | `ProviderRegistered` |
| `resource-market` | `announce_offer` | `Offers` | `ResourceAnnounced` |
| `lease` | `create_lease` | `Leases` | `LeaseCreated` |
| `reputation` | `submit_score` | `ReputationScores` | `ReputationUpdated` |
| `rewards` | `calculate_reward` | `RewardBalances` | `RewardCalculated` |
| `availability` | `submit_heartbeat` | `LastHeartbeat` | `HeartbeatReceived` |

## 3. Integration with Control Plane
The Control Plane should interact with the runtime via the JSON-RPC API:
- **Query**: Use `storage.get` for ranking and status.
- **Action**: Submit signed extrinsics for leases and proofs.
- **Listen**: Subscribe to the event stream to trigger deployment.

## 4. How to Test
Run the pallet tests using:
```bash
cargo test -p runtime --lib
```
