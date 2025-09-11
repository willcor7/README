#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Détecte les règles de pare-feu en double dans un ou plusieurs fichiers CSV Stormshield.

Ce script identifie les doublons en se basant sur une combinaison de champs clés :
- Source
- Destination
- Port de destination
- Protocole

Les commentaires et autres champs peuvent différer.
"""

import argparse
import csv
from pathlib import Path
from typing import Dict, List

# --- Logique réutilisée de converter.py pour une analyse cohérente ---

CSV_ALIASES = {
    "service": ["service", "to_port", "dstport"],
    "from_src": ["from_src", "source"],
    "to_dest": ["to_dest", "destination"],
    "proto": ["proto", "ip_proto"], # Le protocole peut être dans l'une ou l'autre colonne
}

def pick(row: Dict[str, str], keys: List[str]) -> str:
    """
    Récupère la première valeur non vide trouvée dans une ligne pour une liste de clés possibles.
    """
    for k in keys:
        if k in row:
            v = row.get(k, "").strip()
            if v:
                return v
    return ""

def read_csv(path: Path) -> List[Dict[str, str]]:
    """
    Lit un fichier CSV, en attendant une ligne d'en-tête pour définir les colonnes.
    La ligne d'en-tête peut éventuellement commencer par un caractère '#'.
    """
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        all_lines = f.readlines()

    header_line_content = None
    header_line_index = -1
    for i, line in enumerate(all_lines):
        stripped = line.strip()
        if stripped:
            header_line_content = stripped.lstrip('#')
            header_line_index = i
            break

    if header_line_content is None:
        return []

    data_lines = [line for line in all_lines[header_line_index + 1:] if line.strip()]
    delim = ';' if ';' in header_line_content else ','
    original_headers = next(csv.reader([header_line_content], delimiter=delim))

    cleaned_headers = []
    counts = {}
    for h in original_headers:
        stripped_h = h.strip().lstrip('#').strip('"')
        if stripped_h in counts:
            counts[stripped_h] += 1
            cleaned_headers.append(f"{stripped_h}_{counts[stripped_h]}")
        else:
            counts[stripped_h] = 0
            cleaned_headers.append(stripped_h)

    final_rows = []
    reader = csv.reader(data_lines, delimiter=delim)
    for i, fields in enumerate(reader):
        if not any(field.strip() for field in fields):
            continue

        padded_fields = fields + [""] * (len(cleaned_headers) - len(fields))
        row_dict = dict(zip(cleaned_headers, padded_fields[:len(cleaned_headers)]))

        # Nettoyer les valeurs textuelles d'abord
        for key, value in row_dict.items():
            row_dict[key] = value.strip().strip('"') if value is not None else ""

        # Ajouter le numéro de ligne original (entier) APRÈS le nettoyage
        row_dict['original_line'] = header_line_index + 2 + i

        final_rows.append(row_dict)

    return final_rows

# --- Logique principale du détecteur de doublons ---

def find_duplicates(rows: List[Dict[str, str]]) -> Dict:
    """
    Analyse les lignes et renvoie un dictionnaire des doublons trouvés.
    """
    seen_rules = {}
    for row in rows:
        if not pick(row, ["action", "from_src", "to_dest"]):
            continue

        source = pick(row, CSV_ALIASES.get("from_src", ["from_src"])) or "any"
        destination = pick(row, CSV_ALIASES.get("to_dest", ["to_dest"])) or "any"
        dest_port = pick(row, CSV_ALIASES.get("service", ["service"])) or "any"
        protocol = pick(row, CSV_ALIASES.get("proto", ["proto"])) or "any"
        signature = (source, destination, dest_port, protocol)

        occurrence = {
            "file": row.get("source_file", "N/A"),
            "line": row.get("original_line", "N/A"),
            "name": pick(row, ["rule_name"]) or "Sans nom"
        }
        seen_rules.setdefault(signature, []).append(occurrence)

    return {sig: occs for sig, occs in seen_rules.items() if len(occs) > 1}

def format_as_markdown(duplicates: Dict) -> str:
    """
    Formate un dictionnaire de doublons en une table Markdown.
    """
    if not duplicates:
        return "Aucun doublon détecté."

    lines = [
        "| Source | Destination | Port | Protocole | Occurrences |",
        "|---|---|---|---|---|"
    ]

    for sig, occs in duplicates.items():
        source, dest, port, proto = sig
        occurrences_str = "<br>".join(
            [f"- Fichier: `{occ['file']}`, Ligne: `{occ['line']}`, Nom: `\"{occ['name']}\"`" for occ in occs]
        )
        lines.append(f"| {source} | {dest} | {port} | {proto} | {occurrences_str} |")

    return "\n".join(lines)

def write_report(filename: str, content: str):
    """Écrit le contenu dans un fichier."""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

def main():
    """
    Fonction principale pour exécuter la détection de doublons.
    """
    parser = argparse.ArgumentParser(
        description="Détecte les règles de pare-feu en double et les sépare en fichiers de règles et de NAT."
    )
    parser.add_argument(
        "--csv",
        required=True,
        nargs='+',
        help="Chemin vers un ou plusieurs fichiers CSV à analyser.",
    )
    args = parser.parse_args()

    print("Début de l'analyse des doublons...")

    all_rows = []
    for file_path in args.csv:
        path = Path(file_path)
        if not path.exists():
            print(f"ERREUR: Le fichier '{file_path}' n'a pas été trouvé.")
            continue

        print(f"Lecture du fichier : {file_path}")
        rows = read_csv(path)
        for row in rows:
            row['source_file'] = file_path
        all_rows.extend(rows)

    if not all_rows:
        print("Aucune ligne à analyser.")
        return

    # Séparer les lignes en règles (filter) et NAT
    rules_rows = [row for row in all_rows if "local_filter_slot" in str(row.values())]
    nat_rows = [row for row in all_rows if "local_nat_slot" in str(row.values())]

    # Traiter les règles de filtrage
    print("Analyse des doublons de règles de filtrage...")
    rule_duplicates = find_duplicates(rules_rows)
    rule_report = format_as_markdown(rule_duplicates)
    write_report("rules.txt", rule_report)
    print(f"Rapport des règles de filtrage écrit dans rules.txt ({len(rule_duplicates)} doublons trouvés).")

    # Traiter les règles NAT
    print("Analyse des doublons de règles NAT...")
    nat_duplicates = find_duplicates(nat_rows)
    nat_report = format_as_markdown(nat_duplicates)
    write_report("nat.txt", nat_report)
    print(f"Rapport des règles NAT écrit dans nat.txt ({len(nat_duplicates)} doublons trouvés).")

    print("\nAnalyse terminée.")

if __name__ == "__main__":
    main()
