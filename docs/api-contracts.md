# API Contracts - Scheduler

> The network RPC source of truth is `protocol/proto/`. JSON examples in this document are explanatory and must not be used to generate service types.

## Scheduler API (Control Plane)

### POST /schedule
**Request:**
```json
{
  "workload_id": "uuid",
  "profile": "compute_intensive | memory_intensive | storage_intensive | latency_sensitive",
  "requirements": {
    "cpu": 4,
    "ram_mb": 8192,
    "disk_gb": 50,
    "max_latency_ms": 100
  },
  "max_price": 0.10
}
```
**Response:**
```json
{
  "node_id": "0x...",
  "deployment_token": "jwt_token",
  "score": 0.92
}
```

## Provider Registration and Heartbeats

The Agent calls `openinfra.controlplane.v1.ControlPlaneService` using mTLS. Join uses `BeginJoin` and `CompleteJoin`; liveness uses `ReportHeartbeat`. See [Provider Join and Heartbeat Protocol v1](protocol/provider-join-v1.md).

The Control Plane calls `openinfra.agent.v1.ProviderAgentService` for inventory, challenges, deployment, stop, status, health, and metrics. No bearer deployment token is defined in v1.

## Workload API

`SubmitWorkload` accepts an idempotency UUID, a `WorkloadDefinition`, and an OCI image pinned with a lowercase SHA-256 digest. A successful response means only that PostgreSQL durably contains the request in `WORKLOAD_STATE_REQUESTED`; it does not imply scheduling or deployment. Retrying the same request ID and payload returns the same workload, while reusing it with another payload fails.

`GetWorkload` returns the authoritative persisted state. `provider_id`, `lease_id`, and `container_id` remain empty until their corresponding scheduler, finalized blockchain, and Provider Agent confirmations have been committed. The dashboard displays this same projection.

## Blockchain Bridge API

### GET /reputation/{node_id}
**Response:**
```json
{
  "compute": 0.95,
  "storage": 0.80,
  "network": 0.90,
  "availability": 0.99
}
```

### POST /reputation/update
**Request:**
```json
{
  "node_id": "0x...",
  "workload_id": "uuid",
  "metrics": {
    "success": true,
    "perf_ratio": 1.05,
    "uptime_during_task": 1.0
  }
}
```
