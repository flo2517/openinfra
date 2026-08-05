# API Specification - Control Plane

## 1. User API (/v1/workloads)
**POST /create**
- Request: `{ "cpu": 4, "ram": 16, "storage": 100, "image": "ubuntu-22.04", "duration": 3600 }`
- Response: `{ "workload_id": "uuid", "status": "PENDING" }`

**GET /status/{id}**
- Response: `{ "workload_id": "uuid", "status": "RUNNING", "provider_id": "0x...", "ip": "1.2.3.4" }`

## 2. Agent API (gRPC - Internal)
**Service AgentManager**
- `rpc ReportHeartbeat(ReportHeartbeatRequest) returns (ReportHeartbeatResponse)` is the canonical unary v1 heartbeat. Control commands use the separate Provider Agent service.
- `rpc DeployWorkload(WorkloadSpec) returns (DeploymentResponse)`
- `rpc TerminateWorkload(WorkloadId) returns (Response)`

## 3. Blockchain Bridge (Internal)
Interface utilisée par le CP pour interagir avec le runtime Substrate :
- `get_provider_ranking()` $\rightarrow$ Retourne la liste triée des nodes.
- `submit_lease(provider, consumer, resources)` $\rightarrow$ Transaction on-chain.
- `submit_proof(provider, data)` $\rightarrow$ Transaction on-chain.
