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
import re
from collections import Counter
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

def normalize_field(value: str) -> str:
    """
    Normalise un champ contenant potentiellement plusieurs objets séparés
    par des virgules ou des points-virgules. Trie les objets pour rendre la
    signature indépendante de l'ordre.
    """
    if not isinstance(value, str) or not value.strip():
        return ""

    components = [comp.strip() for comp in re.split(r'[,;]', value) if comp.strip()]

    if len(components) > 1:
        components.sort()
        return ",".join(components)

    return value.strip()

# --- Logique principale du détecteur de doublons ---

def find_duplicates(rows: List[Dict[str, str]], debug: bool = False) -> Dict:
    """
    Analyse les lignes et renvoie un dictionnaire des doublons trouvés.
    """
    if debug:
        print("\n--- DÉBUT DU DÉBOGAGE : SIGNATURES GÉNÉRÉES ---")

    seen_rules = {}
    for row in rows:
        if not pick(row, ["action", "from_src", "to_dest"]):
            continue

        source = normalize_field(pick(row, CSV_ALIASES.get("from_src", ["from_src"]))) or "any"
        destination = normalize_field(pick(row, CSV_ALIASES.get("to_dest", ["to_dest"]))) or "any"
        dest_port = normalize_field(pick(row, CSV_ALIASES.get("service", ["service"]))) or "any"
        protocol = pick(row, CSV_ALIASES.get("proto", ["proto"])) or "any"
        action = pick(row, ["action"]) or "any"
        signature = (source, destination, dest_port, protocol, action)

        if debug:
            line_num = row.get('original_line', 'N/A')
            print(f"Ligne {line_num}: Signature = {signature}")

        occurrence = {
            "file": row.get("source_file", "N/A"),
            "line": row.get("original_line", "N/A"),
            "name": pick(row, ["rule_name"]) or "Sans nom",
            "nat_line": row.get("nat_line")
        }
        seen_rules.setdefault(signature, []).append(occurrence)

    return {sig: occs for sig, occs in seen_rules.items() if len(occs) > 1}

def format_as_markdown(duplicates: Dict, report_type: str = 'rules') -> str:
    """
    Formate un dictionnaire de doublons en un rapport Markdown multi-sections.
    """
    if not duplicates:
        return "Aucun doublon détecté."

    report_lines = []
    is_nat_report = report_type == 'nat'
    sorted_signatures = sorted(duplicates.keys(), key=lambda sig: (duplicates[sig][0]['file'], duplicates[sig][0]['line']))

    for sig in sorted_signatures:
        occs = duplicates[sig]
        source, dest, port, proto, action = sig
        header_title = f"### Doublon - Signature : (Source: `{source}`, Destination: `{dest}`, Port: `{port}`, Protocole: `{proto}`, Action: `{action}`)"
        report_lines.append(header_title)
        report_lines.append("")

        if is_nat_report:
            table_header = "| Fichier | Ligne (Fichier) | Ligne (NAT) | Nom de la règle |"
            table_separator = "|---|---|---|---|"
        else:
            table_header = "| Fichier | Ligne | Nom de la règle |"
            table_separator = "|---|---|---|"

        report_lines.append(table_header)
        report_lines.append(table_separator)

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

        if sig != sorted_signatures[-1]:
            report_lines.append("")
            report_lines.append("---")
            report_lines.append("")

    return "\n".join(report_lines)

def generate_delete_script(duplicates: Dict, report_type: str, index: int, is_global: bool) -> List[str]:
    """
    Génère une liste de commandes CLI Stormshield pour supprimer les règles en double.
    """
    commands = []
    rule_type = 'nat' if report_type == 'nat' else 'filter'
    global_param = " global=1" if is_global else ""
    sorted_signatures = sorted(duplicates.keys(), key=lambda sig: (duplicates[sig][0]['file'], duplicates[sig][0]['line']))

    for sig in sorted_signatures:
        occs = duplicates[sig]
        sort_key = 'nat_line' if report_type == 'nat' else 'line'
        sorted_occs = sorted(occs, key=lambda x: (x['file'], x.get(sort_key, 0)))
        name_counts = Counter(occ['name'] for occ in sorted_occs)

        for occ_to_delete in sorted_occs[1:]:
            rule_name = occ_to_delete.get('name')
            command = None
            if report_type == 'nat':
                if rule_name and rule_name != "Sans nom":
                    command = f'CONFIG FILTER RULE REMOVE index={index} type={rule_type} name="{rule_name}"{global_param}'
            else:
                use_position = not rule_name or rule_name == "Sans nom" or name_counts[rule_name] > 1
                if use_position:
                    position = occ_to_delete.get('line')
                    command = f'CONFIG FILTER RULE REMOVE index={index} type={rule_type} position={position}{global_param}'
                else:
                    command = f'CONFIG FILTER RULE REMOVE index={index} type={rule_type} name="{rule_name}"{global_param}'

            if command:
                commands.append(command)

    return commands

def write_report(filename: str, content: str):
    """Écrit le contenu dans un fichier."""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

def main():
    """
    Fonction principale pour exécuter la détection de doublons.
    """
    parser = argparse.ArgumentParser(
        description="Détecte les règles de pare-feu en double, génère des rapports et un script de suppression."
    )
    parser.add_argument(
        "--csv",
        required=True,
        nargs='+',
        help="Chemin vers un ou plusieurs fichiers CSV à analyser.",
    )
    parser.add_argument(
        "--index",
        type=int,
        default=9,
        help="Numéro du slot de la politique à utiliser pour la suppression (défaut: 9).",
    )
    parser.add_argument(
        "--global",
        dest='is_global',
        action="store_true",
        help="Utiliser le contexte global pour la suppression (global=1).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Activer le mode de débogage pour afficher les signatures générées.",
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
    print("\nAnalyse des doublons de règles de filtrage...")
    rule_duplicates = find_duplicates(rules_rows, debug=args.debug)
    rule_report = format_as_markdown(rule_duplicates, report_type='rules')
    write_report("rules.txt", rule_report)
    print(f"Rapport des règles de filtrage écrit dans rules.txt ({len(rule_duplicates)} doublons trouvés).")

    # Traiter les règles NAT
    nat_rows.sort(key=lambda r: r.get('original_line', 0))
    for i, row in enumerate(nat_rows):
        row['nat_line'] = i + 1

    print("\nAnalyse des doublons de règles NAT...")
    nat_duplicates = find_duplicates(nat_rows, debug=args.debug)
    nat_report = format_as_markdown(nat_duplicates, report_type='nat')
    write_report("nat.txt", nat_report)
    print(f"Rapport des règles NAT écrit dans nat.txt ({len(nat_duplicates)} doublons trouvés).")

    # --- Génération du script de suppression ---
    print("\nGénération du script de suppression...")
    delete_commands = []

    rule_delete_commands = generate_delete_script(rule_duplicates, 'rules', args.index, args.is_global)
    if rule_delete_commands:
        delete_commands.append("# Commandes pour supprimer les doublons de règles de filtrage")
        delete_commands.extend(rule_delete_commands)

    nat_delete_commands = generate_delete_script(nat_duplicates, 'nat', args.index, args.is_global)
    if nat_delete_commands:
        if delete_commands: # Ajouter un espace si des commandes de règles existent déjà
            delete_commands.append("")
        delete_commands.append("# Commandes pour supprimer les doublons de règles de NAT")
        delete_commands.extend(nat_delete_commands)

    if delete_commands:
        delete_commands.append("\n# Activer la nouvelle politique de filtrage")
        delete_commands.append("CONFIG FILTER ACTIVATE")
        script_content = "\n".join(delete_commands)
        write_report("Duplicate_to_delete.sh", script_content)
        print(f"Script de suppression généré dans Duplicate_to_delete.sh ({len(rule_delete_commands)} commandes de règles, {len(nat_delete_commands)} commandes NAT).")
    else:
        print("Aucune commande de suppression à générer.")

    print("\nAnalyse terminée.")

if __name__ == "__main__":
    main()
