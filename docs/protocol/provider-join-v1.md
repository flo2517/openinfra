# Provider Join and Heartbeat Protocol v1

## Status and Direction

This is the canonical pre-MVP contract. The Provider Agent is the client of `openinfra.controlplane.v1.ControlPlaneService`; it never joins through its own server and never contacts Substrate directly. `openinfra.agent.v1.ProviderAgentService` remains the Control Plane-to-Agent command surface.

All non-loopback RPCs require mutually authenticated TLS. Protobuf signatures authenticate application payloads and do not replace mTLS.

## Join Sequence

1. The Agent creates a stable Ed25519 identity and sends `BeginJoin` with a unique `request_id`, its raw 32-byte public key, and versions.
2. The Control Plane binds a cryptographically random, single-use nonce to that public key and returns its expiry. Repeating the same request and payload returns the same live result.
3. The Agent signs the byte sequence `openinfra-join-v1\0 || challenge_nonce` and calls `CompleteJoin` with current capabilities.
4. The Control Plane verifies expiry, one-time use, key binding, signature, versions, and input bounds. It commits the provider transactionally to PostgreSQL before returning `NODE_STATUS_ACTIVE`.

No bearer session token is returned. Conflicting reuse of a `request_id` or consumed challenge must fail explicitly.

## Heartbeat Sequence

`ReportHeartbeatRequest.payload` contains a retry identifier, provider ID, persistent monotonic sequence, observation timestamp, and capabilities. The signature input is:

```text
"openinfra-heartbeat-v1\0" || deterministic_protobuf(payload)
```

Both implementations must reject unknown fields in a signing payload before verification and use deterministic Protobuf serialization. The Control Plane verifies the identity, timestamp skew, signature, and sequence, then refreshes Redis. Heartbeat retries with identical request ID and payload are idempotent; changed payloads conflict. PostgreSQL remains authoritative for provider registration.

## State Rules

- `PENDING`: challenge issued or registration not durably committed.
- `ACTIVE`: identity verified and registration committed; recent heartbeat required for scheduling visibility.
- `OFFLINE`: heartbeat timeout; reconstructible from Agent/Redis state.
- `DRAINING` and `MAINTENANCE`: explicitly controlled operational states.

Never return `ACTIVE` solely because an RPC was received.

## Current Implementation

`control-plane/internal/providerjoin` implements challenge creation, Ed25519 verification, idempotency, and transactional PostgreSQL persistence using `control-plane/migrations/000001_provider_join.sql`. `control-plane/cmd/controlplane` exposes the service with mandatory mTLS except for explicit loopback development mode. The Rust `agent-cli --dev join` command performs the two-step exchange.

`ReportHeartbeat` verifies the signed payload and provider identity, rejects stale or replayed sequences, and refreshes a Redis record with a bounded TTL. Scheduling visibility is the intersection of an `ACTIVE` PostgreSQL registration and that fresh Redis record.
