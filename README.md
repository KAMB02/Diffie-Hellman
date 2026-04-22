# Diffie-Hellman Cryptographic Protocol Demonstration

![Rust](https://img.shields.io/badge/Rust-1.51+-green.svg?style=flat-square&logo=rust)
![License](https://img.shields.io/badge/License-Educational-green.svg)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen.svg)

## Description

Ce projet est une démonstration interactive et pédagogique du protocole cryptographique Diffie-Hellman. Il permet de comprendre comment ce protocole permet à deux personnes (Alice et Bob) d'établir une clé secrète partagée sur un canal de communication non sécurisé, tout en montrant comment un attaquant (Ismaël) peut tenter de compromettre cette communication.

## Objectifs Pédagogiques

- Comprendre les bases de la cryptographie moderne
- Visualiser l'échange de clés Diffie-Hellman
- Explorer l'impact de la taille des nombres premiers sur la sécurité
- Découvrir différentes techniques d'attaque cryptographique

## Fonctionnalités

### Interface Console
- Menu interactif pour lancer des démonstrations
- Explications détaillées des paramètres p et g
- Visualisation étape par étape du protocole
- Simulations d'attaques (force brute et intelligente)
- Classification du niveau de sécurité selon la taille du nombre premier

### Interface Graphique (GUI)
- Interface moderne utilisant egui
- Visualisation interactive du protocole
- Représentation graphique des clés et des attaques

## Installation et Utilisation

### Prérequis
- Rust (version 2021 ou supérieure)
- Cargo (gestionnaire de paquets Rust)

### Compilation
```bash
# Compiler le projet
cargo build --release
```

### Lancement

#### Version Console
```bash
cargo run --bin console
```

#### Version Graphique
```bash
cargo run --bin gui
```

## Structure du Projet

```
src/
|-- main.rs          # Point d'entrée de l'application console
|-- main_gui.rs      # Point d'entrée de l'application graphique
|-- dh.rs            # Implémentation du protocole Diffie-Hellman
|-- attack.rs        # Simulations d'attaques cryptographiques
|-- classify.rs      # Classification des niveaux de sécurité
|-- display.rs       # Fonctions d'affichage pour la console
|-- gui.rs           # Interface graphique (ancienne version)
|-- gui_egui.rs      # Interface graphique moderne avec egui
```

## Fonctionnement du Protocole

1. **Génération des paramètres publics** : Choix d'un nombre premier p et d'une base g
2. **Génération des clés privées** : Alice et Bob choisissent chacun un nombre secret a et b
3. **Calcul des clés publiques** : A = g^a mod p et B = g^b mod p
4. **Échange des clés publiques** : Alice et Bob échangent A et B
5. **Calcul de la clé partagée** : Alice calcule B^a mod p, Bob calcule A^b mod p
6. **Résultat** : Les deux obtiennent la même clé secrète partagée

## Attaques Simulées

### Attaque par Force Brute
- Test de toutes les possibilités de clés privées
- Efficace pour les petites valeurs de p

### Attaque Intelligente
- Utilisation d'algorithmes optimisés
- Exploitation des vulnérabilités mathématiques

## Niveaux de Sécurité

- **Très faible** : p < 1000 bits
- **Faible** : 1000-2048 bits  
- **Moyen** : 2048-3072 bits
- **Fort** : 3072-4096 bits
- **Très fort** : > 4096 bits

## Réalisateurs

Ce projet a été réalisé par :

- **KAMB02** - [GitHub](https://github.com/KAMB02)
- **ELISA_734** - [GitHub](https://github.com/Elisa734)

## Contribuer

Les contributions sont bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer des améliorations
- Ajouter de nouvelles fonctionnalités
- Améliorer la documentation

## Technologies Utilisées

- **Rust** : Langage de programmation principal
- **num-bigint** : Gestion des grands nombres
- **colored** : Affichage coloré en console
- **eframe/egui** : Interface graphique moderne
- **tokio** : Programmation asynchrone
