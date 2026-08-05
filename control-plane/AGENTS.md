# Control Plane Guidelines

## Scope

This Go component owns the user API, authentication, Agent Manager, Scheduler, Blockchain Bridge, Workload Orchestrator, PostgreSQL persistence, and Redis-backed ephemeral state.

## Implementation Rules

- Use generated Protobuf contracts. Pass `context.Context`, explicit timeouts, and correlation IDs across boundaries.
- Make commands idempotent. Bound retries, apply backoff with jitter, and distinguish retryable failures.
- PostgreSQL is authoritative for users, workload requests, orchestration state, and lease references. Redis may hold heartbeats, short locks, ranking, and reconstructible caches only.
- Never mark a workload `RUNNING` until the Agent confirms Docker state. Persist transitions and design compensation for partial lease/deploy failures.
- Keep Substrate client details inside the Blockchain Bridge; do not place runtime logic in the domain or Scheduler.
- Validate input, avoid hard-coded secrets, and use structured telemetry. Do not silently discard stream or persistence errors.

## Validation

Run from this directory after `go.mod` exists:

```bash
gofmt -w .
go vet ./...
go test ./...
```

Tests must cover timeouts, retries, idempotence, state transitions, and repository/cache failure behavior.
