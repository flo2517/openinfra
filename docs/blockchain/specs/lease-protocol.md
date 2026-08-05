# Protocole de Lease Resource

Le Lease est le contrat intelligent liant un consommateur à un fournisseur.

## 1. Structure du Contrat
```rust
struct Lease {
    provider_id: Hash,
    consumer_id: Hash,
    workload_id: Hash,
    resources: Resource,        // CPU, RAM, etc.
    duration: BlockHeight,      // Durée du contrat
    price: Balance,             // Prix total ou taux horaire
    reputation_req: u32,        // Score minimum exigé par le client
    status: LeaseStatus,
}
```

## 2. Cycle de Vie (Transitions)
1. **CREATED :** Le Scheduler émet la transaction `lease_resource()`. Le prix estprovisionné (Escrow).
2. **VALIDATED :** Le Provider Agent accepte le lease et confirme la disponibilité.
3. **RUNNING :** Le workload est lancé. L'événement `WorkloadStarted` est émis.
4. **COMPLETED :** Le workload termine normalement. Les fonds sont libérés vers le provider.
5. **FAILED :** Panne technique. Déclenche une investigation de réputation.
6. **EXPIRED :** La durée est atteinte sans signal de fin.

## 3. Gestion des Litiges
En cas de `FAILED` contesté, un pool de validateurs analyse les logs de performance. Si la faute incombe au provider $\rightarrow$ **Slashing** du stake et paiement du consommateur.
