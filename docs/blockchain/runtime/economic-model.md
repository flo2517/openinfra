# Modèle Économique MVP

L'économie repose sur un système de points de réputation convertibles en récompenses.

## 1. Cycle de Valeur
`Contribution Réelle` $\rightarrow$ `Preuve Validée` $\rightarrow$ `Gain de Réputation` $\rightarrow$ `Récompense (Points/Tokens)`.

## 2. Calculs MVP
- **Récompense :**
  $Reward = (\text{Ressources fournies} \times \text{Temps}) \times \text{Multiplicateur de Réputation}$.
- **Pénalité (Slashing) :**
  En cas de `FAILED` lease ou preuve invalide : $\text{Stake} = \text{Stake} \times 0.95$ (Perte de 5%).
- **Staking :**
  Un dépôt minimum est requis pour devenir "Active". Le stake sert de garantie contre la malveillance.

## 3. Proof of Resource MVP (Simplification)
Pour le prototype, nous implémentons uniquement :
**Proof of Availability (PoA)**
- **Mécanisme :** Le validateur demande un hash d'un bloc de données aléatoires stocké en RAM/Disk.
- **Validation :** Si la réponse est correcte et rapide $\rightarrow$ Node disponible.
- **Reporté :** VDF et PoSt complets (trop complexes pour le prototype).
