# Définition des Extrinsics Substrate

Liste des appels déclenchables sur la blockchain.

| Extrinsic | Appelant | Paramètres | Évènements générés | Description |
| :--- | :--- | :--- | :--- | :--- |
| `register_provider` | Provider signé | `public_key` | `ProviderRegistered` | Auto-inscription conservée pour compatibilité. |
| `register_provider_for` | `RegistrationOrigin` | `provider, public_key` | `ProviderRegistered` | Inscription déléguée utilisée par le bridge du Control Plane. |
| `set_status` | `StatusOrigin` | `provider, status` | `StatusChanged` | Applique uniquement une transition autorisée du graphe de statut. |
| `announce_resources` | Provider | `CPU, RAM, Storage, Caps` | `ResourceAnnounced` | Publie l'offre de ressources. |
| `submit_proof` | Rep. Validator | `ProviderID, ProofType, Hash` | `ProofSubmitted` | Soumet une preuve de contribution. |
| `create_lease` | Consumer/CP | `ProviderID, ResourceReq, Duration` | `LeaseCreated` | Verrouille ressources et fonds. |
| `complete_lease` | Provider | `LeaseID` | `WorkloadCompleted` | Signale la fin du service. |
| `update_reputation` | System/Validator | `ProviderID, NewScore` | `ReputationUpdated` | Mise à jour du score suite à preuve. |
| `claim_reward` | Provider | `Period` | `RewardIssued` | Débloque les points/tokens gagnés. |
