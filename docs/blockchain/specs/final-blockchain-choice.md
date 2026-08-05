# Intégration Provider Agent & Choix Blockchain

## 1. Cycle de vie de l'Agent
- **Identité :** L'agent génère une paire de clés au premier boot. Il appelle `register_provider` avec son stake. Son `NodeID` est le hash de sa clé publique.
- **Ressources :** L'agent scanne son matériel $\rightarrow$ génère un `ResourceHash` $\rightarrow$ appelle `ResourceAnnounced`.
- **Réception Lease :** L'agent écoute l'événement `LeaseCreated` via un WebSocket vers la blockchain.
- **Preuve :** L'agent répond aux challenges PoR et soumet la transaction `ProofSubmitted`.
- **Récompenses :** L'agent surveille `RewardIssued` et peut `Claim` ses tokens.

## 2. Justification du choix Substrate vs Cosmos SDK

| Critère | Substrate | Cosmos SDK | Verdict |
| :--- | :--- | :--- | :--- |
| **Modularité** | Pallets Wasm (très flexible) | Modules Go (robuste) | Substrate |
| **Runtime** | Upgradable sans fork | Upgradable via gouvernance | Substrate |
| **Performance** | Optimisé pour exécution locale | Optimisé pour inter-chain (IBC) | Substrate |
| **PoC matériel**| Intégration Wasm facilitée | Plus complexe en Go | Substrate |

**Choix Final : Substrate**
Substrate permet de coder la logique de réputation et de validation de preuves directement dans le runtime via Wasm, ce qui est crucial pour un système où les règles de récompense peuvent évoluer rapidement sans interrompre le réseau.

### Spécifications Techniques :
- **Consensus :** BABE (Block production) + GRANDPA (Finality).
- **Validateurs :** Nodes avec le stake le plus élevé et la meilleure réputation.
- **Token :** Token utilitaire pour le paiement des ressources et le staking.
- **Staking :** Modèle "Nominated Proof of Stake" (NPoS).
