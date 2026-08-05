# Modèle de Proof of Resource (PoR)

Le PoR assure que les ressources déclarées sont physiquement présentes et disponibles.

## 1. Méthodes de Preuve

### Compute (CPU/GPU)
- **Mécanisme :** "Computation Challenge".
- **Processus :** Le validateur envoie une fonction déterministe complexe (ex: VDF ou calcul de hash itératif sur un seed aléatoire).
- **Preuve :** L'agent renvoie le résultat signé. Le coût temporel de réponse prouve la puissance de calcul.
- **Validation :** Vérification du résultat et du timestamp de réponse.

### Storage (Disk)
- **Mécanisme :** "Proof of Spacetime" (PoSt) simplifié.
- **Processus :** Le validateur demande le hash de segments aléatoires d'un fichier "sentinelle" déposé sur le disque du provider.
- **Preuve :** `Hash(Seed + Data_Segment)`.
- **Validation :** Comparaison avec le hash attendu.

### Network (Bandwidth/Latency)
- **Mécanisme :** "Active Probing".
- **Processus :** Le Control Plane et des nodes tiers effectuent des tests de débit et de latence (ICMP/TCP).
- **Preuve :** Signature des résultats de tests par plusieurs peers.
- **Validation :** Moyenne pondérée des résultats pour éviter les rapports biaisés.

## 2. Gouvernance des Challenges
- **Fréquence :** Aléatoire, entre 1 heure et 24 heures.
- **Déclencheur :** Validateurs sélectionnés par la blockchain (Random Selection).
- **Validation :** Effectuée on-chain via Wasm (pour Compute/Storage) ou off-chain par consensus de validateurs.
- **Stockage On-chain :** Seul le `ChallengeID` et le `ResultHash` sont stockés pour minimiser la taille.
