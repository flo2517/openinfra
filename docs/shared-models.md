# Shared Models Specification - OpenInfra Network

This document defines the common data structures used across all network components. To ensure interoperability, any change to these models must be versioned and coordinated across the Blockchain, Scheduler, Provider Agent, and Control Plane.

## 1. Node Identity
**Object: `NodeIdentity`**
Represents a unique entity participating as a provider in the network.

```json
{
  "node_id": "string (uint256/address)",
  "public_key": "string (hex)",
  "protocol_version": "string (semver)",
  "agent_version": "string (semver)",
  "capabilities": "ResourceCapability",
  "status": "string (online | offline | draining | maintenance)"
}
```
- **Usage**: Found in Blockchain Registry, Scheduler Node Cache, and Provider Agent Heartbeats.

---

## 2. Resource Capability
**Object: `ResourceCapability`**
Defines the hardware limits and current availability of a node.

```json
{
  "cpu_total": "float (cores)",
  "cpu_available": "float (cores)",
  "ram_total": "int (MB)",
  "ram_available": "int (MB)",
  "storage_total": "int (GB)",
  "storage_available": "int (GB)",
  "gpu": {
    "model": "string",
    "vram_total": "int (MB)",
    "vram_available": "int (MB)",
    "count": "int"
  },
  "bandwidth": {
    "ingress_mbps": "int",
    "egress_mbps": "int"
  }
}
```

---

## 3. Reputation Vector
**Object: `ReputationVector`**
A multi-dimensional score representing a provider's trust level.

```json
{
  "compute": "float (0.0-1.0)",
  "storage": "float (0.0-1.0)",
  "network": "float (0.0-1.0)",
  "availability": "float (0.0-1.0)",
  "reliability": "float (0.0-1.0)",
  "global": "float (0.0-1.0)"
}
```
- **Type**: Fixed-point decimal / Float.
- **Precision**: 4 decimal places.
- **Source**: Blockchain Layer (aggregated from Proof-of-Execution).
- **Update Frequency**:
    - *Dimension-specific*: After every workload completion.
    - *Global*: Once per network epoch (e.g., every 24h).

---

## 4. Workload Definition
**Object: `WorkloadDefinition`**
The specification of the task to be deployed.

```json
{
  "workload_id": "string (uuid)",
  "profile": "string (compute_intensive | memory_intensive | storage_intensive | latency_sensitive)",
  "requirements": {
    "cpu": "float",
    "ram": "int",
    "storage": "int",
    "gpu": "int"
  },
  "constraints": {
    "max_latency": "int (ms)",
    "min_reputation": "float",
    "max_price": "float"
  },
  "duration": "int (seconds, 0 for indefinite)"
}
```

---

## 5. Lease Object
**Object: `Lease`**
The "contract" binding a consumer to a provider for a specific workload.

```json
{
  "lease_id": "string (uuid)",
  "provider_id": "string (node_id)",
  "consumer_id": "string (address)",
  "workload_id": "string (uuid)",
  "start": "timestamp (ISO8601)",
  "end": "timestamp (ISO8601 | null)",
  "state": "string (pending | active | completed | failed | expired)"
}
```

---

## 6. Event Envelope
**Object: `EventEnvelope`**
The standard wrapper for all asynchronous communication in the network.

```json
{
  "event_id": "string (uuid)",
  "event_type": "string (e.g., NodeAvailable, WorkloadCompleted)",
  "timestamp": "timestamp (ISO8601)",
  "source": "string (component_id)",
  "payload": "object (dynamic based on event_type)",
  "signature": "string (cryptographic signature for authenticity)"
}
```
