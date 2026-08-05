# Substrate Runtime Specification v0.1 - OpenInfra Network

Ce document constitue la spécification technique finale pour l'implémentation du runtime Substrate.

## 1. Architecture des Pallets

### `pallet-provider-registry`
Gère l'identité et le cycle de vie des fournisseurs.
- **Storage :**
    - `Providers`: `StorageMap<AccountId, Provider>`
- **Extrinsics :**
    - `register_provider(pubkey)` : Enregistre un nouveau node.
    - `update_status(node_id, new_status)` : (Admin/System) Change l'état du node.
- **Events :** `ProviderRegistered`, `StatusChanged`.
- **Errors :** `AlreadyRegistered`, `UnauthorizedStatusChange`.

### `pallet-resource-market`
Gère les offres de ressources disponibles.
- **Storage :**
    - `Offers`: `StorageMap<AccountId, ResourceOffer>`
- **Extrinsics :**
    - `announce_offer(cpu, ram, storage, capabilities)` : Publie les ressources.
    - `remove_offer()` : Retire l'offre du marché.
- **Events :** `ResourceAnnounced`, `ResourceRemoved`.
- **Errors :** `ProviderNotRegistered`.

### `pallet-lease`
Gère les contrats d'utilisation des ressources.
- **Storage :**
    - `Leases`: `StorageMap<LeaseId, Lease>`
- **Extrinsics :**
    - `create_lease(provider, consumer, resources, duration)` : Initie un contrat.
    - `complete_lease(lease_id)` : Clôture le contrat.
- **Events :** `LeaseCreated`, `LeaseCompleted`, `LeaseExpired`.
- **Errors :** `LeaseNotFound`, `InvalidProvider`.

### `pallet-reputation`
Moteur de scoring basé sur les performances.
- **Storage :**
    - `ReputationScores`: `StorageMap<AccountId, u32>`
- **Extrinsics :**
    - `submit_score(provider, score_delta, proof)` : (Validator) Modifie le score.
    - `update_reputation(provider, new_score)` : (System) Force un score.
- **Events :** `ReputationUpdated`.
- **Errors :** `InvalidProof`, `ScoreOutOfBounds`.

### `pallet-rewards`
Calcul et attribution des points de récompense.
- **Storage :**
    - `RewardBalances`: `StorageMap<AccountId, u64>`
- **Extrinsics :**
    - `calculate_reward(lease_id)` : Calcule les points suite à la fin d'un lease.
    - `claim_reward()` : Transfère les points vers le wallet de l'utilisateur.
- **Events :** `RewardCalculated`, `RewardClaimed`.
- **Errors :** `InsufficientPoints`.

### `pallet-availability`
Vérification de la disponibilité (MVP Proof of Availability).
- **Storage :**
    - `LastHeartbeat`: `StorageMap<AccountId, BlockNumber>`
- **Extrinsics :**
    - `submit_heartbeat()` : Le provider signale sa présence.
    - `validate_challenge(provider, response)` : Valide un challenge de disponibilité.
- **Events :** `HeartbeatReceived`, `ChallengeValidated`.
- **Errors :** `ChallengeTimeout`, `InvalidResponse`.

---

## 2. Cycle de Vie Provider

| État | Transition Vers | Responsable | Condition |
| :--- | :--- | :--- | :--- |
| `REGISTERED` | `VERIFIED` | Validator | Validation réussie du premier challenge PoA. |
| `VERIFIED` | `ACTIVE` | System | Annonce de ressources via `announce_offer`. |
| `ACTIVE` | `SUSPENDED` | System | Manque de heartbeats ou score trop bas. |
| `SUSPENDED` | `ACTIVE` | System | Nouveau challenge PoA réussi. |
| `ACTIVE/SUSP` | `REMOVED` | Admin | Fraude avérée ou demande de sortie. |

---

## 3. Cycle de Vie Lease

| État | Transition Vers | Déclencheur | Événement |
| :--- | :--- | :--- | :--- |
| `CREATED` | `ACTIVE` | Confirmation déploiement Agent | `LeaseStarted` |
| `ACTIVE` | `COMPLETED` | Terminaison Workload | `LeaseCompleted` |
| `ACTIVE` | `EXPIRED` | Bloc `end` atteint | `LeaseExpired` |
| `ACTIVE` | `DISPUTED` | Signalement erreur client | `LeaseDisputed` |

---

## 4. Modèle de Récompense (MVP)

### Formule de Calcul
$\text{Points} = (\text{Unités Ressources} \times \text{Durée}) \times \left( 1 + \frac{\text{Reputation}}{1000} \right) \times \text{AvailabilityScore}$

**Exemple :**
- Ressources : 10 unités (ex: 8 vCPU + 16GB RAM)
- Durée : 100 blocs
- Reputation : 500 (sur 1000) $\rightarrow$ Multiplicateur 1.5
- Availability : 1.0 (100% de heartbeats)
- **Total :** $10 \times 100 \times 1.5 \times 1.0 = 1500 \text{ points}$.

---

## 5. Stratégie Tokenless $\rightarrow$ Token

**V0.1 (Témoin) :**
- Utilisation d'un ledger interne (`RewardBalances`) enregistrant des points non-transférables.
- Aucune valeur marchande, uniquement un ranking.

**Migration V0.2+ :**
1. **Tokenisation :** Remplacement des points par un Token natif Substrate.
2. **Staking :** Verrouillage de tokens pour devenir `VERIFIED`.
3. **Gouvernance :** Vote sur les paramètres de récompense via `pallet-democracy`.

---

## 6. Interface Control Plane $\leftrightarrow$ Runtime

### Appels sortants (Control Plane $\rightarrow$ BC)
- `register_provider(pubkey)`
- `create_lease(provider, consumer, res, dur)`
- `submit_proof(provider, data)`
- `get_reputation(provider)`

### Flux entrants (BC $\rightarrow$ Control Plane)
- `ProviderRegistered` $\rightarrow$ Mise à jour index nodes.
- `LeaseCreated` $\rightarrow$ Ordre de déploiement à l'Agent.
- `ReputationUpdated` $\rightarrow$ Recalcul du ranking scheduler.
- `RewardCalculated` $\rightarrow$ Notification utilisateur.
