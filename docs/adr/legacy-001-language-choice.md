# ADR 001: Selection of Go for Core Components

> Historical proposal, superseded by current ADR-001 and ADR-002. It is not authoritative for the MVP.

## Status
Proposed

## Context
The system requires a language capable of high-performance networking, concurrent resource management (handling multiple VMs/containers), and efficient system-level integration (interfacing with libvirt, WireGuard, and ZFS).

## Decision
We will use **Go (Golang)** for the Control Plane and the Provider Agent.

## Rationale
- **Concurrency**: Goroutines are ideal for managing asynchronous tasks like heartbeat monitoring and workload orchestration.
- **Static Binaries**: Go compiles to static binaries, simplifying deployment on diverse provider machines without managing runtime environments.
- **Ecosystem**: Strong library support for gRPC, Docker API, and cloud-native tools.
- **Performance**: Near-C performance with safer memory management.

## Consequences
- Developers must be proficient in Go.
- Some low-level C-bindings might be needed for specific ZFS/KVM calls (via cgo).
