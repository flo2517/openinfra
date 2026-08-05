# Modèle d'Événements Blockchain OpenInfra Network

Ce document définit les événements émis par la blockchain et leur impact sur l'écosystème.

| Événement | Émetteur | Données | Consommateurs | Effet Attendu |
| :--- | :--- | :--- | :--- | :--- |
| `NodeRegistered` | BC | `NodeID, PubKey, Stake` | Control Plane | Indexation du node comme "Pending". |
| `NodeVerified` | BC | `NodeID, HardwareHash` | Control Plane | Passage du status "Pending" $\rightarrow$ "Active". |
| `ResourceAnnounced` | BC | `NodeID, ResourceHash` | Control Plane | Mise à jour du catalogue de ressources. |
| `ResourceValidated` | BC | `NodeID, ValidationStatus` | Control Plane | Confirmation que les ressources sont réelles. |
| `WorkloadRequested` | BC | `WorkloadID, ConsumerID, Req` | Scheduler | Déclenchement de l'algorithme de matching. |
| `LeaseCreated` | BC | `LeaseID, NodeID, WorkloadID` | Provider Agent | Signal de provisionnement immédiat. |
| `WorkloadStarted` | BC | `LeaseID, StartBlock` | Control Plane | Début du décompte de facturation/récompense. |
| `WorkloadCompleted` | BC | `LeaseID, QualityScore` | BC, Control Plane | Déclenchement du calcul de la récompense. |
| `ProofSubmitted` | BC | `NodeID, ProofID, Hash` | Validateurs | Vérification de la preuve par les pairs. |
| `ReputationUpdated` | BC | `NodeID, OldScore, NewScore` | Scheduler | Ré-ordonnancement du ranking des nodes. |
| `RewardIssued` | BC | `NodeID, Amount, Period` | Provider Agent | Notification de paiement au fournisseur. |
| `PenaltyApplied` | BC | `NodeID, Amount, Reason` | Provider Agent | Alerte de slashing et perte de stake. |
