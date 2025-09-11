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

        # Ajouter le numéro de ligne comme attendu par l'utilisateur (commence à 1 après l'en-tête).
        # L'ancien calcul `header_line_index + 2 + i` donnait le numéro de ligne réel dans le fichier.
        row_dict['original_line'] = header_line_index + 1 + i

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
            "name": pick(row, ["rule_name"]) or "Sans nom",
            "nat_line": row.get("nat_line")  # Sera None pour les règles de filtrage
        }
        seen_rules.setdefault(signature, []).append(occurrence)

    return {sig: occs for sig, occs in seen_rules.items() if len(occs) > 1}

def format_as_markdown(duplicates: Dict, report_type: str = 'rules') -> str:
    """
    Formate un dictionnaire de doublons en un rapport Markdown multi-sections.
    Chaque groupe de doublons est présenté dans sa propre section pour une lisibilité maximale.
    """
    if not duplicates:
        return "Aucun doublon détecté."

    report_lines = []
    is_nat_report = report_type == 'nat'

    # Trier les groupes de doublons par leur première apparition (fichier, ligne)
    sorted_signatures = sorted(duplicates.keys(), key=lambda sig: (duplicates[sig][0]['file'], duplicates[sig][0]['line']))

    for sig in sorted_signatures:
        occs = duplicates[sig]
        source, dest, port, proto = sig

        # --- En-tête de la section pour ce groupe de doublons ---
        header_title = f"### Doublon - Signature : (Source: `{source}`, Destination: `{dest}`, Port: `{port}`, Protocole: `{proto}`)"
        report_lines.append(header_title)
        report_lines.append("")  # Ligne vide pour l'espacement

        # --- Tableau des occurrences pour ce groupe ---
        if is_nat_report:
            table_header = "| Fichier | Ligne (Fichier) | Ligne (NAT) | Nom de la règle |"
            table_separator = "|---|---|---|---|"
        else:
            table_header = "| Fichier | Ligne | Nom de la règle |"
            table_separator = "|---|---|---|"

        report_lines.append(table_header)
        report_lines.append(table_separator)

        # Trier les occurrences au sein d'un groupe par nom de fichier puis par numéro de ligne
        sort_key = 'nat_line' if is_nat_report else 'line'
        sorted_occs = sorted(occs, key=lambda x: (x['file'], x.get(sort_key, 0)))

        for occ in sorted_occs:
            file = f"`{occ['file']}`"
            line = f"`{occ['line']}`"
            name = f"`{occ['name']}`"

            if is_nat_report:
                nat_line_val = f"`{occ.get('nat_line', 'N/A')}`"
                report_lines.append(f"| {file} | {line} | {nat_line_val} | {name} |")
            else:
                report_lines.append(f"| {file} | {line} | {name} |")

        # --- Séparateur horizontal pour le prochain groupe ---
        if sig != sorted_signatures[-1]:
            report_lines.append("")
            report_lines.append("---")
            report_lines.append("")

    return "\n".join(report_lines)

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

    # Séparer les lignes en règles (filter) et NAT de manière robuste
    rules_rows = [row for row in all_rows if any("local_filter_slot" in str(v) for v in row.values())]
    nat_rows = [row for row in all_rows if any("local_nat_slot" in str(v) for v in row.values())]

    # Traiter les règles de filtrage
    print("Analyse des doublons de règles de filtrage...")
    rule_duplicates = find_duplicates(rules_rows)
    rule_report = format_as_markdown(rule_duplicates, report_type='rules')
    write_report("rules.txt", rule_report)
    print(f"Rapport des règles de filtrage écrit dans rules.txt ({len(rule_duplicates)} doublons trouvés).")

    # Traiter les règles NAT
    # D'abord, trier les lignes NAT par leur ligne d'origine pour un comptage relatif cohérent
    nat_rows.sort(key=lambda r: r.get('original_line', 0))
    # Ajouter le numéro de ligne relatif
    for i, row in enumerate(nat_rows):
        row['nat_line'] = i + 1

    print("Analyse des doublons de règles NAT...")
    nat_duplicates = find_duplicates(nat_rows)
    nat_report = format_as_markdown(nat_duplicates, report_type='nat')
    write_report("nat.txt", nat_report)
    print(f"Rapport des règles NAT écrit dans nat.txt ({len(nat_duplicates)} doublons trouvés).")

    print("\nAnalyse terminée.")

if __name__ == "__main__":
    main()
