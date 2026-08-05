# Cross-Component Test Guidelines

This directory contains integration tests, E2E scenarios, and non-sensitive fixtures. Tests verify contracts and component interaction; they must not introduce business logic.

- Keep tests reproducible, isolated, deterministic where possible, and bounded by explicit timeouts.
- Allocate unique resources per run and clean containers, databases, keys, and temporary files automatically, including after failures.
- Cover failure scenarios: invalid identity, stale heartbeat, unavailable dependency, duplicate command, retry exhaustion, partial deployment, and restart recovery.
- Verify idempotence and authoritative state transitions; never accept a mocked success as E2E evidence.
- Fixtures must contain synthetic credentials only and clearly identify them as non-production.
