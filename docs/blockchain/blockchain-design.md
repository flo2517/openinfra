# Design de la Blockchain OpenInfra Network

## 1. Objectifs & Philosophie
La blockchain sert de couche de vérité (Single Source of Truth) pour l'identité, la réputation et la distribution financière. Elle ne gère pas le flux de données des workloads (off-chain) mais valide les preuves de travail et l'état du réseau.

## 2. Choix Technologiques
**Technologie recommandée : Substrate (Polkadot SDK)**
- **Pourquoi ?** Permibilité de créer des "Pallets" (modules) personnalisés pour la réputation et le staking sans subir les contraintes d'une VM générique (EVM). Support natif du Wasm et flexibilité du consensus.
- **Compromis :** Courbe d'apprentissage plus élevée que l'EVM, mais performance et modularité supérieures pour un cas d'usage infrastructure.

## 3. Modèle de Données & Stockage

### On-Chain (Minimaliste pour scalabilité)
- **Registry des Nodes :** `NodeID` $\rightarrow$ `{PublicKey, Status, HardwareCaps (Hash), Stake}`.
- **Réputation :** `NodeID` $\rightarrow$ `ReputationScore`.
- **Balances :** Solde des tokens pour récompenses et staking.
- **Commitments :** Hash des SLAs promis par le fournisseur.

### Off-Chain (Stocké par le Control Plane / P2P)
- **Inventaire détaillé :** Liste complète CPU/GPU/RAM (trop lourd pour on-chain).
- **Logs de performance :** Métriques Prometheus brutes.
- **Détails des Workloads :** Images Docker, configurations de VM.

## 4. Mécanismes Core

### A. Logique de Réputation (Inspirée de Bittensor)
La réputation n'est pas auto-déclarée mais attribuée.
- **Validation Croisée :** Des "Validator Nodes" échantillonnent les ressources des "Provider Nodes".
- **Score :** $R_{t+1} = R_t + (\text{Performance} \times \text{Fiabilité}) - \text{Pénalités}$.
- **Poids :** Plus la réputation est haute, plus le node est susceptible d'être choisi par le scheduler.

### B. Système de Récompenses
- **Emission :** Inflation programmée du token.
- **Distribution :** Les récompenses sont distribuées proportionnellement au produit $(\text{Réputation} \times \text{Ressources fournies})$.
- **Staking :** Un dépôt obligatoire (collateral) pour rejoindre le réseau.

## 5. Sécurité & Anti-Fraude
- **Preuve de Contribution (PoC) :** Utilisation de "Challenge-Response" (ex: calcul d'un hash spécifique sur un segment de RAM/Disque) pour prouver l'existence réelle des ressources.
- **Slashing :** En cas de fraude avérée (ex: simulation de ressources) ou de downtime non justifié, une partie du stake est brûlée.

## 6. Modèle de Transactions

| Transaction | Input | Effet On-Chain |
| :--- | :--- | :--- |
| `RegisterNode` | `PubKey, HardwareHash, Stake` | Ajout au registry, verrouillage du stake. |
| `UpdateReputation` | `NodeID, Proof, NewScore` | Mise à jour du score (réservé aux validateurs). |
| `ClaimReward` | `NodeID, Period` | Transfert des tokens accumulés vers le wallet. |
| `SlashNode` | `NodeID, Evidence` | Réduction du stake et chute de réputation. |
