# Interface Control Plane $\rightarrow$ Blockchain

Définition du client API utilisé par le Control Plane pour interagir avec Substrate.

## 1. Méthodes de Lecture (Query)
- `get_provider_ranking(req)` :
    - Filtre les `ResourceOffer` et trie par `Provider.reputation`.
    - Retourne : `List<{NodeID, Score, AvailableResources}>`.
- `get_reputation(node_id)` :
    - Retourne le score actuel d'un provider.
- `get_lease_status(lease_id)` :
    - Retourne l'état actuel d'un contrat (Running, Completed, etc.).

## 2. Méthodes d'Écriture (Submit)
- `create_lease(provider_id, workload_hash, duration)` :
    - Appelle l'extrinsic `create_lease`.
- `submit_proof(provider_id, proof_data)` :
    - Le Control Plane peut agir comme validateur et soumettre des preuves de performance.
- `report_failure(lease_id)` :
    - Initie une procédure de slashing si le workload a échoué.
