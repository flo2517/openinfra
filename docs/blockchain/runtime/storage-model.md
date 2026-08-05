# Modèle de Stockage On-Chain

Définition des structures et des Storage Maps Substrate.

## 1. Structures de Données

```rust
// pallet-provider
struct Provider {
    id: AccountId,
    owner: AccountId,
    public_key: [u8; 32],
    status: ProviderStatus, // { Pending, Active, Slashing }
    reputation: u32,
    stake: Balance,
}

// pallet-resources
struct ResourceOffer {
    provider_id: AccountId,
    cpu: u32,
    ram: u64,
    storage: u64,
    capabilities: Vec<Capability>, // { GPU, NVMe, etc. }
}

// pallet-leasing
struct Lease {
    lease_id: u64,
    provider: AccountId,
    consumer: AccountId,
    resources: ResourceOffer,
    start: BlockNumber,
    end: BlockNumber,
    state: LeaseState, // { Created, Running, Completed, Failed }
}

// pallet-reputation
struct Proof {
    provider: AccountId,
    proof_type: ProofType, // { Availability, Compute }
    hash: H256,
    timestamp: BlockNumber,
    score: i32,
}
```

## 2. Storage Maps (Substrate)

| Map | Type | Key | Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `Providers` | `StorageMap` | `AccountId` | `Provider` | Registry global des nodes. |
| `Offers` | `StorageMap` | `AccountId` | `ResourceOffer` | Ressources annoncées par node. |
| `Leases` | `StorageMap` | `u64` | `Lease` | Index des contrats de location. |
| `Reputation` | `StorageMap` | `AccountId` | `u32` | Score actuel du node. |
| `Proofs` | `StorageMap` | `H256` | `Proof` | Historique des preuves soumises. |
