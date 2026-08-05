# ADR-006: Docker as the MVP Workload Runtime

**Status:** Accepted

## Context

The MVP needs a widely available workload runtime with a mature Rust API and observable lifecycle.

## Decision

Use Docker through bollard for MVP workload execution. Kubernetes, VM orchestration, and alternative runtimes are deferred.

## Consequences

The Agent must enforce resource/PID limits, least privilege, image policy, workload-count limits, and persistent container mapping before reporting success.
