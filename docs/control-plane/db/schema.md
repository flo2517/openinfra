# Database Schema - Control Plane

## 1. Modèles de Données (PostgreSQL)

### Table: `users`
- `id`: UUID (PK)
- `wallet_address`: String (Unique)
- `created_at`: Timestamp

### Table: `providers` (Cache local du registry BC)
- `node_id`: String (PK - Blockchain Address)
- `last_heartbeat`: Timestamp
- `status`: Enum (ACTIVE, INACTIVE, UNKNOWN)
- `current_load`: JSON (CPU/RAM utilisés)

### Table: `workloads` (Suivi détaillé)
- `id`: UUID (PK)
- `user_id`: UUID (FK)
- `provider_id`: String (FK)
- `lease_id`: String (Blockchain Lease ID)
- `status`: Enum (PENDING, DEPLOYING, RUNNING, COMPLETED, FAILED)
- `spec`: JSON (Requirements)
- `created_at`: Timestamp
- `ended_at`: Timestamp

## 2. Modèle de Cache (Redis)
- `heartbeat:{node_id}` $\rightarrow$ TTL 30s.
- `ranking_cache` $\rightarrow$ TTL 60s (Liste des meilleurs nodes).
