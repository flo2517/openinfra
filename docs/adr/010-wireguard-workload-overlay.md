# ADR-010: Short-lived WireGuard workload overlays

## Status

Accepted for the MVP preparation phase.

## Context

Workloads must not receive a network peer merely because a deployment request
exists. A peer is authorized by a finalized Lease, must be isolated to the
workload container namespace, and must disappear when the workload stops or
the lease is revoked. WireGuard private keys must never enter PostgreSQL,
Redis, logs, command-line arguments, or Protobuf responses.

## Decision

The Control Plane owns the lifecycle coordinator in
`control-plane/internal/wireguard`. It validates a non-empty, non-expired Lease,
allocates a short-lived UDP port from a bounded range, and calls a privileged
backend to configure and attach the peer. The backend is an interface so unit
tests do not require `CAP_NET_ADMIN`; the Linux implementation uses `wg` and
explicit namespace helper commands and keeps a generated key in a mode-0600
temporary file only for the configure operation.

The orchestrator calls Attach only after finalized on-chain lease confirmation
and Agent Docker RUNNING confirmation. If attachment fails, the workload is
stopped and retried; RUNNING is never persisted with a partial overlay. Stop
revokes the namespace attachment and peer before the Lease is completed.
Revoke is idempotent, and Rotate always generates a new key and port.

WireGuard is disabled unless `WIREGUARD_INTERFACE` is configured. Deployments
must provide the privileged helper boundary on the provider host; the workload
container never receives the Docker socket or host network privileges.

## Consequences

The MVP keeps overlay state in process memory and reconstructs it through the
normal workload/lease recovery path. A future multi-Control-Plane deployment
must move peer reservations to a replicated off-chain coordinator while
retaining the same Backend contract and key-isolation rules.
