# Control Plane Architecture - OpenInfra Network

Le Control Plane (CP) est l'orchestrateur central qui fait le pont entre les utilisateurs, la Blockchain Layer et les Provider Agents.

## 1. Architecture Logique
Le CP est conçu comme un ensemble de services modulaires :

- **User API Service**: Point d'entrée REST/gRPC pour les clients.
- **Agent Manager**: Gestionnaire de connexions gRPC bidirectionnelles avec les agents.
- **Scheduler Integration**: Logique de matching basée sur le ranking blockchain.
- **Blockchain Bridge**: Client Substrate pour les transactions et l'écoute d'événements.
- **Persistence Layer**: Stockage d'état local pour le cache et le suivi des workloads.

## 2. Choix Technologiques
- **Langage :** Go (pour sa performance en concurrence et son support gRPC natif).
- **Base de données :** PostgreSQL (Données structurées, ACID pour les états de workloads).
- **Cache :** Redis (Heartbeats des agents, cache du ranking blockchain).
- **Communication :**
    - `User <-> CP`: REST / JSON-RPC.
    - `CP <-> Agent`: gRPC (Bi-directional streaming).
    - `CP <-> Blockchain`: JSON-RPC (via Substrate API).

## 3. Flux de Données et Événements
Le CP transforme les événements blockchain en actions d'orchestration :

`Blockchain: LeaseCreated` $\rightarrow$ `CP: Match agent` $\rightarrow$ `CP $\rightarrow$ Agent: DeployWorkload` $\rightarrow$ `Agent: Running` $\rightarrow$ `CP: Update State`.
