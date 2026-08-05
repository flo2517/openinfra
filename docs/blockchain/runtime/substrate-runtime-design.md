# Substrate Runtime Design - OpenInfra Network

Ce document définit l'implémentation technique du runtime pour la Blockchain Layer.

## 1. Architecture du Runtime
Le runtime est basé sur un modèle de **Pallets** isolées communiquant via des événements et des appels internes.

### Pallets Core :
- `pallet-provider` : Gestion du registry, des identités et du statut.
- `pallet-resources` : Gestion des offres de ressources et mapping.
- `pallet-leasing` : Cycle de vie des contrats de location.
- `pallet-reputation` : Moteur de score et validation des preuves.
- `pallet-staking` : Gestion du collatéral et slashing.

## 2. Consensus & Rôles
- **Consensus :** BABE + GRANDPA.
- **Blockchain Validators :** Nodes assurant la production et la finalité des blocs (Sécurité réseau).
- **Reputation Validators :** Nodes (pouvant être différents des validateurs BC) chargés d'échantillonner les ressources et de soumettre des `Proof` transactions.
- **Distinction :** Le validator BC valide la *transaction* (signature, solde), le reputation validator valide la *vérité technique* (le provider a-t-il vraiment 32Go de RAM ?).
