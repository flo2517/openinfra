# Network Flows & Communication Protocols

## 1. Resource Request Flow (End-to-End)
1. **Request**: User sends a JSON request to `API Gateway` (e.g., 4 vCPU, 16GB RAM, GPU=True).
2. **Matching**: `Global Scheduler` queries the `Blockchain Registry` for available nodes matching specs with high reputation scores.
3. **Selection**: Scheduler selects the optimal Provider Node based on cost/latency.
4. **Provisioning**: `Orchestrator` sends a gRPC command to the `Provider Agent` to create the workload.
5. **Execution**: `Provider Agent` invokes `libvirt` (VM) or `Docker` (Container).
6. **Networking**: `Provider Agent` configures a new `WireGuard` peer and updates the Control Plane to notify other linked workloads.
7. **Confirmation**: Agent returns the workload IP and status to the Orchestrator.

## 2. Reputation & Reward Flow
1. **Heartbeat**: `Provider Agent` sends a signed heartbeat to the Control Plane every $N$ seconds. The Control Plane maintains reconstructible liveness state and submits only validated consensus summaries through its Blockchain Bridge.
2. **Monitoring**: `Control Plane` pulls metrics from `Provider Agent` via Prometheus.
3. **Validation**: If a workload fails or metrics drop, the `Reputation System` on the blockchain reduces the provider's score.
4. **Settlement**: At the end of the billing period, the `Payment Logic` distributes rewards proportionally to the (Reputation $\times$ Resource Use) metric.

## 3. Recovery Flow (Node Failure)
1. **Detection**: `Control Plane` detects a missing heartbeat from a Provider Node.
2. **Rescheduling**: `Global Scheduler` identifies the affected workloads.
3. **Restart**: Workloads are redeployed on the next best available node.
4. **Storage Recovery**: If ZFS snapshots were replicated, the new node pulls the latest state from a peer node or backup.

## 4. Protocol Stack Details

| Layer | Protocol | Description | Security |
| :--- | :--- | :--- | :--- |
| **External API** | REST/gRPC | User $\leftrightarrow$ Control Plane | TLS 1.3 + JWT |
| **Internal Control** | gRPC | Control Plane $\leftrightarrow$ Agent | mTLS (Private CA) |
| **Blockchain** | JSON-RPC | All $\leftrightarrow$ Blockchain | Signed Transactions |
| **Data Plane** | WireGuard | Workload $\leftrightarrow$ Workload | Noise Protocol Framework |
| **Telemetry** | Prometheus | Agent $\rightarrow$ VictoriaMetrics | Basic Auth / TLS |
