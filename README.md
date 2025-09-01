# Outils de Gestion pour Firewall Stormshield

Cette suite d'outils Python est conçue pour automatiser et simplifier la gestion des règles de firewall sur les équipements Stormshield. Elle permet d'exporter, de convertir, de valider et de comparer des configurations de filtrage, facilitant ainsi les migrations, les déploiements en masse et les audits de sécurité.

## Flux de travail principal

Les scripts sont conçus pour être utilisés dans un processus en trois étapes :

1.  **`exporter.py`** : Extrait les règles de filtrage depuis une source (par exemple, un équipement existant) pour les sauvegarder dans un format CSV.
2.  **`converter.py`** : Prend un ou plusieurs fichiers CSV et les convertit en commandes NSRPC (CLI Stormshield), tout en validant les dépendances (objets, interfaces) pour garantir une importation sans erreur.
3.  **`rule_comparator.py`** : Compare un jeu de règles source (exporté) à un jeu de règles final pour identifier et générer les commandes des règles manquantes, assurant ainsi la cohérence entre les configurations.

---

## Prérequis et Installation

### 1. Python
Assurez-vous que **Python 3.x** est installé sur votre machine.

### 2. Dépendances (Installation hors ligne)
Certains scripts nécessitent la bibliothèque `paramiko`. Si vous devez l'installer sur un système sans accès à Internet, suivez la procédure ci-dessous.

<details>
<summary><b>Cliquez pour voir les instructions d'installation hors ligne de Paramiko</b></summary>

Ce guide explique comment télécharger **Paramiko** et ses dépendances pour une installation sur une machine cible spécifique : **Python 3.13** sur **Linux 64-bit** (`manylinux2014_x86_64`).

#### Étape 1 : Téléchargement des paquets (Machine en ligne)

Sur une machine avec accès à Internet, exécutez la commande suivante pour télécharger tous les paquets nécessaires dans un dossier `wheelhouse`.

```bash
python -m pip download \
    --dest ./wheelhouse \
    --only-binary=:all: \
    --implementation cp \
    --python-version 313 \
    --abi cp313 \
    --platform manylinux2014_x86_64 \
    "paramiko[all]"
```

**Conseil :** Il est recommandé de créer un fichier `requirements.txt` sur la machine en ligne pour figer les versions des paquets.
```bash
# Dans un environnement où paramiko est installé
pip freeze > requirements.txt
```
Transférez le dossier `wheelhouse` et le fichier `requirements.txt` sur la machine cible.

#### Étape 2 : Installation sur la machine cible (Hors ligne)

1.  **Créez et activez un environnement virtuel** pour une installation propre.
    ```bash
    # Assurez-vous que python3.13 est le bon exécutable
    python3.13 -m venv ~/venvs/paramiko313
    source ~/venvs/paramiko313/bin/activate
    ```

2.  **Installez les paquets** depuis les fichiers locaux.
    ```bash
    # L'option --no-index empêche la connexion à Internet
    pip install --no-index --find-links=~/wheelhouse -r requirements.txt
    ```
Votre bibliothèque est maintenant prête à être utilisée.

</details>

---

## Utilisation Détaillée des Scripts

### 1. `exporter.py` - Exportation des Règles
Ce script est la première étape du processus. Il est utilisé pour extraire les informations sur les règles de filtrage et les objets depuis un équipement Stormshield et les sauvegarder dans des fichiers CSV.

*(Note : La description détaillée de ce script est basée sur son rôle dans le flux de travail global.)*

**Usage typique :**
```bash
python3 exporter.py --host <firewall_ip> --user <username> --output-dir ./exports
```

### 2. `converter.py` - Conversion CSV vers NSRPC
Ce script convertit les règles de firewall d'un fichier CSV en commandes NSRPC. Il valide que les objets et interfaces existent avant de générer les commandes, séparant les règles "sûres" de celles nécessitant une intervention manuelle.

#### Fonctionnalités
-   **Conversion CSV vers NSRPC** : Transforme les lignes CSV en commandes `CONFIG FILTER RULE INSERT`.
-   **Validation des Dépendances** : Vérifie l'existence des objets (hôtes, services) et des interfaces.
-   **Séparation des Règles** : Crée `rules_safe.txt` (prêtes à l'emploi) et `rules_pending.txt` (dépendances manquantes).
-   **Rapport de Dépendances** : Génère `dependencies_missing.txt` avec la liste des éléments manquants.
-   **Création Automatique d'Hôtes** : Peut générer des commandes pour créer les objets de type hôte manquants.

#### Format du CSV d'entrée
Le script attend un fichier CSV avec une ligne d'en-tête (pouvant commencer par `#`). Le délimiteur peut être `,` ou `;`.
**Exemple d'en-tête :**
```csv
#rule_name,#comment,#state,#action,#from_src,#to_dest,#to_port,#from_if,#to_if
```

#### Usage
```bash
python3 converter.py --csv <path_to_input.csv> [options]
```
**Arguments principaux :**
-   `--csv PATH` : (Requis) Un ou plusieurs fichiers CSV d'entrée.
-   `--objects-file PATH` : Fichier listant les objets existants pour la validation.
-   `--interfaces-file PATH` : Fichier listant les interfaces existantes.
-   `--output-directory DIR` : Répertoire de sortie pour les fichiers générés.
-   `--create-hosts` : Active la création automatique des objets hôtes.
-   `--activate` : Ajoute la commande `CONFIG FILTER ACTIVATE` à la fin du fichier `rules_safe.txt`.

### 3. `rule_comparator.py` - Comparateur de Règles
Ce script compare un ou plusieurs fichiers CSV de règles "source" à un fichier CSV "final" de référence. Il identifie les règles présentes dans la source mais absentes de la destination et génère les commandes CLI pour les ajouter.

#### Fonctionnalités
-   Compare plusieurs sources à une seule destination.
-   Identifie les colonnes nécessaires à partir de l'en-tête du CSV.
-   Génère les commandes `CONFIG FILTER RULE INSERT` pour les règles manquantes.
-   Permet de personnaliser l'index de la politique de filtrage et le niveau de log.

#### Format des fichiers CSV
Les fichiers CSV doivent contenir une ligne d'en-tête commençant par `#`.
-   **Fichiers source** : Doivent contenir `rule_name`, `comment`, `state`, `action`, `from_src`, `to_dest`, `to_port`.
-   **Fichier final** : Doit contenir au minimum `rule_name` pour la comparaison.

#### Usage
```bash
python rule_comparator.py --source <source1.csv> --source <source2.csv> --final <final.csv> --output <commands.cli> [options]
```
**Arguments :**
-   `--source PATH`: (Requis, multiple) Chemin vers un fichier CSV source.
-   `--final PATH`: (Requis) Chemin vers le fichier CSV final de référence.
-   `--output PATH`: (Requis) Fichier de sortie pour les commandes CLI.
-   `--policy-index NUM`: (Optionnel) Index de la politique de filtrage (défaut : `9`).

---

## Licence

Ce projet est distribué sous la licence MIT. Veuillez consulter le fichier `LICENSE` pour plus de détails.
