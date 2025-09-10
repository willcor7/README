# Outils de Gestion pour Firewall Stormshield

Cette suite d'outils Python est conçue pour automatiser et simplifier la gestion des règles de firewall sur les équipements Stormshield. Elle permet d'exporter, de convertir, de valider, de comparer et de détecter les doublons dans les configurations de filtrage.

## Flux de travail et Outils

Les scripts sont conçus pour être utilisés de manière modulaire :

1.  **`exporter.py`** : Extrait les règles de filtrage et autres configurations depuis un équipement Stormshield via SSH et les sauvegarde dans des fichiers texte.
2.  **`converter.py`** : Prend un ou plusieurs fichiers CSV de règles et les convertit en commandes NSRPC (CLI Stormshield). Il valide les dépendances (objets, interfaces), gère les différences entre les règles de filtrage et de NAT, et peut même créer des objets hôtes manquants. Il peut traiter les fichiers CSV de manière entrelacée pour conserver la séquence des règles.
3.  **`rule_comparator.py`** : Compare un jeu de règles source à un jeu de règles final pour identifier et générer les commandes des règles manquantes, en utilisant la même logique de construction de commandes que le convertisseur.
4.  **`duplicate_detector.py`** : Analyse un ou plusieurs fichiers CSV pour trouver des règles en double en se basant sur une signature (source, destination, port, protocole) et génère un rapport des doublons trouvés.

---

## Prérequis et Installation

### 1. Python
Assurez-vous que **Python 3.8+** est installé sur votre machine.

### 2. Dépendances (Installation hors ligne)
Certains scripts (comme `exporter.py`) nécessitent la bibliothèque `paramiko`. Si vous devez l'installer sur un système sans accès à Internet, suivez la procédure ci-dessous.

<details>
<summary><b>Cliquez pour voir les instructions d'installation hors ligne de Paramiko</b></summary>

Ce guide explique comment télécharger **Paramiko** et ses dépendances pour une installation sur une machine cible spécifique.

#### Étape 1 : Téléchargement des paquets (Machine en ligne)
Sur une machine avec accès à Internet, exécutez la commande suivante pour télécharger tous les paquets nécessaires dans un dossier `wheelhouse`.
```bash
python3 -m pip download --dest ./wheelhouse "paramiko"
```

#### Étape 2 : Installation sur la machine cible (Hors ligne)
1.  Transférez le dossier `wheelhouse` sur la machine cible.
2.  **Installez les paquets** depuis les fichiers locaux.
    ```bash
    # L'option --no-index empêche la connexion à Internet
    # L'option --find-links indique à pip où trouver les paquets
    python3 -m pip install --no-index --find-links=./wheelhouse paramiko
    ```
Votre bibliothèque est maintenant prête à être utilisée.
</details>

---

## Utilisation Détaillée des Scripts

### `converter.py`
Convertit les règles de firewall d'un fichier CSV en commandes NSRPC.
```bash
python3 converter.py --csv <path_to_input.csv> [options]
```
**Arguments principaux :**
-   `--csv PATH` : (Requis) Un ou plusieurs fichiers CSV d'entrée.
-   `--objects-file PATH` : Fichier listant les objets existants pour la validation.
-   `--interfaces-file PATH` : Fichier listant les interfaces existantes.
-   `--output-directory DIR` : Répertoire de sortie.
-   `--create-hosts` : Active la création automatique des objets hôtes.
-   `--activate` : Ajoute la commande `CONFIG FILTER ACTIVATE`.

### `rule_comparator.py`
Compare des ensembles de règles et génère les commandes pour les règles manquantes.
```bash
python3 rule_comparator.py --source <source.csv> --final <final.csv> --output <commands.cli>
```
**Arguments :**
-   `--source PATH`: (Requis, multiple) Fichier(s) CSV source.
-   `--final PATH`: (Requis) Fichier CSV de référence.
-   `--output PATH`: (Requis) Fichier de sortie pour les commandes.

### `duplicate_detector.py`
Détecte les règles en double dans un ou plusieurs fichiers CSV.
```bash
python3 duplicate_detector.py --csv <fichier1.csv> <fichier2.csv>
```
**Argument :**
-   `--csv PATH`: (Requis, multiple) Fichier(s) CSV à analyser.

### `exporter.py`
Exporte la configuration d'un équipement Stormshield.
```bash
python3 exporter.py --host <ip_firewall> --user <utilisateur> --output-prefix <prefixe_fichier>
```
**Arguments principaux :**
-   `--host HOST`: (Requis) Adresse IP de l'équipement.
-   `--user USER`: Nom d'utilisateur (défaut: `admin`).
-   `--output-prefix PREFIX`: (Requis) Préfixe pour les noms des fichiers de sortie.
-   `--output-dir DIR`: Répertoire de sortie.
-   `--collect-*`: Divers flags pour collecter des informations spécifiques (sfctl, dhcp, etc.).
