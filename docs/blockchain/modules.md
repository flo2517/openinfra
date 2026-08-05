# Schéma des Modules Blockchain (Substrate Pallets)

```mermaid
graph TD
    A[Substrate Runtime] --> B[Pallet Identity]
    A --> C[Pallet ProviderRegistry]
    A --> D[Pallet Reputation]
    A --> E[Pallet Staking]
    A --> F[Pallet Rewards]

    B -->|Identifie| C
    C -->|Fournit données| D
    D -->|Influence| F
    E -->|Garantit| C
    E -->|Pénalise| D
```

### Description des Modules :
1. **Pallet Identity :** Gestion des clés publiques et mapping avec les identités humaines/organisations.
2. **Pallet ProviderRegistry :** Gestion du cycle de vie des nodes (Join, Leave, UpdateCaps).
3. **Pallet Reputation :** Moteur de scoring basé sur les preuves de validation.
4. **Pallet Staking :** Gestion du collatéral, verrouillage et slashing.
5. **Pallet Rewards :** Logique de distribution des tokens basée sur le score de réputation.
