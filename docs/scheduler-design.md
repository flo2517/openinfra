# Scheduler Design - OpenInfra Network

## 1. Overview
The distributed scheduler determines the optimal provider node for a given workload based on multidimensional reputation, real-time resource availability, and workload-specific profiles.

## 2. Multidimensional Reputation Model
Instead of a scalar value, reputation is now a vector $\vec{R}$ derived from blockchain proofs:
- **Compute Reputation ($R_{comp}$):** Success rate and performance of CPU/GPU tasks.
- **Storage Reputation ($R_{stor}$):** Data integrity and I/O throughput consistency.
- **Network Reputation ($R_{net}$):** Latency stability and bandwidth guarantees.
- **Availability Reputation ($R_{avail}$):** Uptime history and SLA compliance.

**Weighted Reputation Score ($S_{rep}$):**
$S_{rep} = (C_{comp} \cdot R_{comp}) + (C_{stor} \cdot R_{stor}) + (C_{net} \cdot R_{net}) + (C_{avail} \cdot R_{avail})$
*Where $C$ coefficients are defined by the `WorkloadProfile`.*

## 3. Node Resource Model
Nodes distinguish between capacity and current availability:
- **Total Resources:** Static hardware limits (CPU cores, Total RAM, Total Disk).
- **Available Resources:** Dynamic free capacity (CPU free, RAM free, Disk free).

## 4. Workload Profiles
The scheduler adjusts scoring weights based on the profile:
- **Compute Intensive:** High weight on $R_{comp}$ and `cpu_free`.
- **Memory Intensive:** High weight on $R_{comp}$ and `ram_free`.
- **Storage Intensive:** High weight on $R_{stor}$ and `disk_free`.
- **Latency Sensitive:** High weight on $R_{net}$ and physical location/latency.

## 5. Scoring Algorithm (Updated)
$Score(n) = (W_{perf} \cdot S_{perf}) + (W_{rep} \cdot S_{rep}) + (W_{rel} \cdot S_{rel}) - (W_{cost} \cdot S_{cost})$

- $S_{perf}$ is calculated using `available_resources`.
- $S_{rep}$ is calculated using the weighted multidimensional reputation.

## 6. Feedback Loop
`Workload Completed` $\rightarrow$ `Collect Metrics` $\rightarrow$ `Verify vs SLA` $\rightarrow$ `Update Blockchain Reputation`.
