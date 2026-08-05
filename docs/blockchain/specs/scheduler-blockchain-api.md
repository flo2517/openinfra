# API Blockchain $\leftrightarrow$ Scheduler

Le Scheduler utilise ces interfaces pour optimiser le placement des workloads.

## 1. Requête de Ranking (`get_provider_ranking`)
Permet de trouver le meilleur node pour un profil spécifique.

**Entrée :**
```json
{
  "cpu": 8,
  "ram": 32,
  "storage": 100,
  "workload_profile": "compute_intensive", // Optimise pour GPU ou CPU
  "min_reputation": 500
}
```

**Sortie :**
```json
[
  {
    "node_id": "0xabc...",
    "reputation": 850,
    "available_resources": { "cpu": 16, "ram": 64, "storage": 500 },
    "score": 98.5 // Score composite (Réputation * Disponibilité / Prix)
  },
  ...
]
```

## 2. Gestion du Cycle de Vie
- `create_lease(provider_id, workload_hash, ...)` : Initie le contrat.
- `cancel_lease(lease_id)` : Annule le contrat avant lancement.
- `report_incident(lease_id, evidence_hash)` : Signale une défaillance pour déclencher le slashing.
