# OpenInfra Network Architecture

## 1. Overview
OpenInfra Network is a decentralized cloud provider inspired by Bittensor. It allows resource providers to lease compute (CPU, GPU, RAM) and storage to users, with value distribution managed by a reputation-based blockchain layer.

## 2. Global Architecture
The system is divided into four primary layers:

### A. Blockchain Layer (The Trust Anchor)
- **Purpose**: Identity, Registry, Reputation, and Settlement.
- **Key Functions**:
    - Node Identity (Public Keys).
    - Resource Registry (What is available where).
    - Reputation Scoring (Performance vs. Promise).
    - Reward Distribution (Smart Contracts).

### B. Control Plane (The Orchestrator)
- **Purpose**: High-level management and scheduling.
- **Components**:
    - **API Gateway**: Entry point for users.
    - **Global Scheduler**: Matches user requests to the best provider based on cost/reputation/specs.
    - **User Management**: Auth and Billing.
    - **Orchestration Engine**: Coordinates deployment steps across providers.

### C. Provider Agent (The Edge Worker)
- **Purpose**: Local resource management and workload execution.
- **Components**:
    - **Hardware Inventory**: Real-time monitoring of local specs.
    - **Virtualization Manager**: Interface for KVM/libvirt and Docker.
    - **Metrics Exporter**: Pushes resource usage to the Control Plane/Blockchain.
    - **Secure Tunnel**: WireGuard interface for workload networking.

### D. Infrastructure Layer (The Physicals)
- **Compute**: KVM for VMs, Docker for Containers.
- **Storage**: ZFS for local volumes, MinIO for object storage.
- **Network**: WireGuard for P2P overlay network.
- **Observability**: Prometheus/VictoriaMetrics.

## 3. Component Communications

| Source | Destination | Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| User | Control Plane | HTTPS/gRPC | Resource Request / Management |
| Control Plane | Blockchain | JSON-RPC | Registry Lookup / Rewards |
| Control Plane | Provider Agent | gRPC (mTLS) | Workload Scheduling / Command |
| Provider Agent | Blockchain | JSON-RPC | Identity Heartbeat / Proof-of-Work |
| Provider Agent | Control Plane | gRPC / Prometheus | Metrics & Health Reporting |
| Workload A | Workload B | WireGuard (UDP) | Decentralized P2P Networking |

## 4. Technical Protocols
- **Control Plane $\leftrightarrow$ Agent**: gRPC over mTLS for low latency and strong security.
- **Overlay Network**: WireGuard for encrypted L3 connectivity between distributed nodes.
- **State Sync**: Blockchain-based event sourcing for the global registry.
- **Observability**: OpenTelemetry for distributed tracing.

## 5. Technical Risks & Mitigations

| Risk | Impact | Mitigation |
| :--- | :--- | :--- |
| **Sybil Attack** | High | Staking requirement and reputation-based filtering. |
| **Node Churn** | High | Erasure coding for storage and automated migration for VMs. |
| **Resource Hoarding** | Medium | Dynamic pricing based on scarcity and demand. |
| **Network Latency** | Medium | Geo-aware scheduling using Latency-based routing. |
| **Malicious Host** | Critical | Trusted Execution Environments (TEE) or Periodic Verifiable Computation. |

## 6. Technological Choices (Proposed)
- **Language**: Go (for agents and control plane - performance/concurrency).
- **Blockchain**: Substrate or EVM-compatible (for flexibility and smart contracts).
- **Virtualization**: libvirt/KVM (Industry standard for isolation).
- **Networking**: WireGuard (Performance and simplicity).
- **Storage**: ZFS (Data integrity and snapshots).
- **Metrics**: VictoriaMetrics (Scalable Prometheus alternative).
