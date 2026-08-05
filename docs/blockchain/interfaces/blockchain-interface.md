# Interfaces Blockchain OpenInfra Network

Ce document définit le protocole de communication entre la Blockchain Layer, le Control Plane et les Provider Agents.

## 1. Choix d'Architecture Finaux
- **Framework :** Substrate (confirmé).
- **API :** gRPC pour les communications haute performance entre Control Plane $\leftrightarrow$ Blockchain ; JSON-RPC pour les agents.
- **Données :**
    - *On-chain* : Identité, Hash des capacités, Score de réputation, État du Stake, Contrats de location (IDs et Hash).
    - *Off-chain* : Inventaire détaillé, Métriques Prometheus, Images de workloads.
- **Gestion des clés :** SRPK (Schnorrkel) pour les signatures, gérées localement par le Provider Agent via un HSM ou un keystore sécurisé.

## 2. Modèles de Données (Structures)

### Provider
```rust
struct Provider {
    id: Hash,                // Identifier unique blockchain
    public_key: PublicKey,   // Clé pour signature des preuves
    location: Region,        // Zone géographique (ex: EU-West-1)
    capabilities_hash: Hash, // Hash de la structure Resource (off-chain)
    reputation_score: u32,   // Score de 0 à 1000
    status: NodeStatus,      // { Active, Inactive, Slashing, Pending }
}
```

### Resource (Stockée Off-chain / Hash on-chain)
```rust
struct Resource {
    cpu: u32,                // Nb de cœurs
    ram: u64,                // Go
    storage: u64,            // Go
    gpu: Option<GpuSpec>,    // Modèle et VRAM
    bandwidth: u32,          // Mbps
}
```

### Workload (Contrat de location)
```rust
struct Workload {
    id: Hash,
    requirements: Resource,  // Besoins minimums
    provider: Hash,          // NodeID assigné
    duration: BlockHeight,   // Durée prévue
    status: WorkloadStatus,  // { Requested, Running, Completed, Failed }
}
```

### Reward
```rust
struct Reward {
    provider: Hash,
    contribution: u64,       // Quantité de ressources x temps
    score: u32,              // Score de qualité constaté
    amount: Balance,         // Token amount
}
```

## 3. API et Événements Blockchain

### Transactions (Writes)
| Action | Appel API | Paramètres | Effet |
| :--- | :--- | :--- | :--- |
| **Enregistrement** | `register_provider()` | `PubKey, ResourceHash, Stake` | Création du NodeID, verrouillage stake. |
| **Update Capacités**| `update_resources()` | `NodeID, NewResourceHash` | Mise à jour du hash des ressources. |
| **Publier Score** | `update_reputation()`| `NodeID, Proof, NewScore` | Modif score (réservé aux validateurs). |
| **Valider Challenge**| `submit_poc()` | `NodeID, ChallengeID, Response` | Validation de la présence matérielle. |
| **Créer Contrat** | `lease_resource()` | `NodeID, WorkloadHash, Duration` | Verrouille la ressource pour l'utilisateur. |
| **Attribuer Reward**| `distribute_reward()`| `NodeID, Amount` | Transfert de tokens au provider. |
| **Pénaliser** | `apply_slash()` | `NodeID, Evidence` | Brûle une partie du stake. |

### Événements (Events)
- `ProviderJoined(NodeID)` $\rightarrow$ Déclenche l'indexation par le Scheduler.
- `ReputationChanged(NodeID, Old, New)` $\rightarrow$ Mise à jour du cache de tri du Scheduler.
- `LeaseStarted(WorkloadID, NodeID)` $\rightarrow$ Notification à l'Agent pour provisionnement.
- `ResourceUnavailable(NodeID)` $\rightarrow$ Déclenche la migration des workloads.

## 4. Interactions Système

### Control Plane
- **Lecture :** Query le registry des nodes et les scores de réputation pour le ranking.
- **Écriture :** Initie les contrats de location (`lease_resource`) et signale les preuves de fraude.
- **Réaction :** Le scheduler réagit aux événements `ProviderJoined` et `ResourceUnavailable`.

### Provider Agent
- **Identité :** Génère sa paire de clés localement $\rightarrow$ soumet la `PubKey` via `register_provider`.
- **Preuves :** Répond aux challenges envoyés par le Control Plane/Validateurs $\rightarrow$ soumet `submit_poc` on-chain.
- **Cycle de vie :** Reçoit l'identité blockchain lors de la confirmation de la transaction d'enregistrement.

## 5. Flux de Travail (Workflows)

### A. Onboarding d'un Agent
`Agent (Génère Clés)` $\rightarrow$ `TX: register_provider(PubKey, Stake)` $\rightarrow$ `Blockchain (Valide & Stocke)` $\rightarrow$ `Event: ProviderJoined` $\rightarrow$ `Control Plane (Indexe le node)`.

### B. Provisionnement VM
`User (Requête)` $\rightarrow$ `Control Plane` $\rightarrow$ `Query: Reputation Ranking` $\rightarrow$ `TX: lease_resource(NodeID, Workload)` $\rightarrow$ `Event: LeaseStarted` $\rightarrow$ `Agent (Déploie VM/Container)`.

### C. Cycle de Récompense
`Agent (Envoie métriques)` $\rightarrow$ `Control Plane (Valide Performance)` $\rightarrow$ `TX: update_reputation(NodeID, Score)` $\rightarrow$ `TX: distribute_reward(NodeID, Amount)` $\rightarrow$ `Agent (Reçoit Tokens)`.
