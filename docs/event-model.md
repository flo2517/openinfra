# Event Model - Scheduling

| Event | Producer | Consumer | Payload |
| :--- | :--- | :--- | :--- |
| `NodeAvailable` | Provider Agent | Scheduler | `node_id, total_res, avail_res, price` |
| `NodeSelected` | Scheduler | Control Plane | `workload_id, node_id, score` |
| `WorkloadStarted`| Provider Agent | Monitoring | `workload_id, node_id, timestamp` |
| `WorkloadCompleted`| Provider Agent | Scheduler | `workload_id, exit_code, duration` |
| `PerformanceMeasured`| Monitoring | Reputation Engine| `workload_id, node_id, actual_metrics` |
| `ReputationUpdated`| Blockchain Layer| Scheduler | `node_id, new_rep_vector` |
