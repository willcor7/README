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
import unicodedata
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# --- Logic copied from converter.py for consistency ---

MAX_NSRPC_LINE = 1024
ALLOWED_ACTIONS = {"pass", "block", "drop", "bypass", "deleg", "reset", "log", "decrypt", "nat"}

CSV_TO_NSRPC_MAP = {
    "rule_name": "rulename", "comment": "comment", "state": "state", "action": "action",
    "count": "count", "rate": "rate", "set_tos": "settos", "inspection": "inspection",
    "service": "service", "log_level": "loglevel", "schedule": "schedule",
    "route": "route", "no_conn_log": "noconnlog", "tos": "tos", "ip_proto": "ipproto",
    "proto": "proto", "from_user_type": "srcusertype", "from_user_domain": "srcuserdomain",
    "from_user_method": "srcusermethod", "from_src": "srctarget", "from_geo": "srcgeo",
    "from_ip_rep": "srciprep", "from_host_rep": "srchostrep", "from_port": "srcport",
    "from_if": "srcif", "via": "via", "to_dest": "dsttarget", "to_geo": "dstgeo",
    "to_ip_rep": "dstiprep", "to_host_rep": "dsthostrep", "to_port": "dstport",
    "to_if": "dstif", "nat_before_vpn": "beforevpn", "nat_from_target": "natsrctarget",
    "nat_from_arp": "natsrcarp", "nat_from_port": "natsrcport",
    "nat_from_load_balancing": "natsrclb", "nat_to_target": "natdsttarget",
    "nat_to_arp": "natdstarp", "nat_to_port": "natdstport",
    "nat_to_load_balancing": "natdstlb",
}

CSV_ALIASES = {
    "service": ["service", "to_port", "dstport"],
    "from_src": ["from_src", "source"],
    "to_dest": ["to_dest", "destination"],
    "nat_from_target": ["nat_from_target", "natsrctarget"],
    "nat_to_target": ["nat_to_target", "natdsttarget"],
    "nat_to_port": ["nat_to_port", "natdstport"],
    "log_level": ["log_level", "loglevel"],
}

VALID_FILTER_TOKENS = {
    "rulename", "comment", "state", "action", "count", "rate", "settos",
    "inspection", "service", "loglevel", "schedule", "route", "noconnlog",
    "tos", "ipproto", "proto", "srcusertype", "srcuserdomain", "srcusermethod",
    "srctarget", "srcgeo", "srciprep", "srchostrep", "srcport", "srcif", "via",
    "dsttarget", "dstgeo", "dstiprep", "dsthostrep", "dstport", "dstif"
}

def pick(row: Dict[str, str], keys: List[str]) -> str:
    for k in keys:
        if k in row:
            v = row.get(k, "").strip()
            if v:
                return v
    return ""

def is_valid_ip_or_network(s: str) -> bool:
    ip_re = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
    cidr_re = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/(?:[0-2]?\d|3[0-2])$")
    range_re = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)-(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
    return bool(ip_re.match(s) or cidr_re.match(s) or range_re.match(s))

def format_nsrpc_param(value: str) -> str:
    nfkd = unicodedata.normalize("NFKD", value)
    clean_val = "".join(c for c in nfkd if not unicodedata.combining(c)).strip()
    if not clean_val:
        return '""'
    is_simple = re.match(r'^[a-zA-Z0-9_.-]+$', clean_val) is not None
    if clean_val.lower() == 'any' or is_valid_ip_or_network(clean_val) or is_simple:
        return clean_val
    else:
        return f'"{clean_val.replace("\"", r"\"")}"'

def coerce_action(val: str) -> Optional[str]:
    v = (val or "").strip().lower()
    if v in ALLOWED_ACTIONS:
        return v
    mapping = {"allow": "pass", "accept": "pass", "deny": "drop"}
    return mapping.get(v)

def read_csv(path: Path) -> List[Dict[str, str]]:
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
    for fields in reader:
        if not any(field.strip() for field in fields):
            continue
        padded_fields = fields + [""] * (len(cleaned_headers) - len(fields))
        row_dict = dict(zip(cleaned_headers, padded_fields[:len(cleaned_headers)]))
        for key, value in row_dict.items():
            row_dict[key] = value.strip().strip('"') if value is not None else ""
        final_rows.append(row_dict)
    return final_rows

def classify_row(row: Dict[str, str]) -> str:
    type_slot = pick(row, ["type_slot"])
    if "nat" in type_slot.lower():
        return "NAT"
    if pick(row, ["action"]).lower() == "nat":
        return "NAT"
    if pick(row, ["nat_from_target"]) or pick(row, ["nat_to_target"]):
        return "NAT"
    return "FILTER"

def build_filter_cmd(row: Dict[str, str], default_slot: int, position: int) -> Tuple[Optional[str], Optional[str]]:
    parts = ["CONFIG FILTER RULE INSERT"]
    slot_str = pick(row, ["policy", "slot", "index"])
    slot = int(slot_str) if slot_str.isdigit() else default_slot
    parts.extend([f"index={slot}", "type=filter", f"position={position}"])

    rule_name = pick(row, CSV_ALIASES.get("rule_name", ["rule_name"]))
    comment = pick(row, CSV_ALIASES.get("comment", ["comment"]))
    if not rule_name:
        rule_name = comment if comment else f"FilterRule-{position:04d}"
        if rule_name == comment: comment = ""

    nfkd = unicodedata.normalize("NFKD", rule_name.replace("\n", " ").strip())
    rule_name = "".join(c for c in nfkd if not unicodedata.combining(c))
    if len(rule_name) > 64: rule_name = rule_name[:61] + "..."
    if rule_name: parts.append(f"rulename={format_nsrpc_param(rule_name)}")
    if comment: parts.append(f"comment={format_nsrpc_param(comment)}")

    for csv_key, nsrpc_token in CSV_TO_NSRPC_MAP.items():
        if csv_key in ["rule_name", "comment"]: continue
        if nsrpc_token not in VALID_FILTER_TOKENS: continue # Allow only specific filter params

        aliases = CSV_ALIASES.get(csv_key, [csv_key])
        value = pick(row, aliases)
        if value:
            if nsrpc_token == "action":
                value = coerce_action(value)
                if not value: return None, f"action de filtre inconnue: {pick(row, aliases)!r}"
            if nsrpc_token == "ipproto" and "," in value:
                value = value.split(',')[0]
            parts.append(f"{nsrpc_token}={format_nsrpc_param(value)}")

    cmd = " ".join(parts)
    return (cmd, None) if len(cmd) <= MAX_NSRPC_LINE else (None, "ligne NSRPC générée trop longue")

def build_nat_cmd(row: Dict[str, str], default_slot: int, position: int) -> Tuple[Optional[str], Optional[str]]:
    parts = ["CONFIG FILTER RULE INSERT"]
    slot_str = pick(row, ["policy", "slot", "index"])
    slot = int(slot_str) if slot_str.isdigit() else default_slot
    parts.extend([f"index={slot}", "type=nat", "action=nat", f"position={position}"])

    rule_name = pick(row, CSV_ALIASES.get("rule_name", ["rule_name"]))
    comment = pick(row, CSV_ALIASES.get("comment", ["comment"]))
    if not rule_name:
        rule_name = comment if comment else f"NatRule-{position:04d}"
        if rule_name == comment: comment = ""

    nfkd = unicodedata.normalize("NFKD", rule_name.replace("\n", " ").strip())
    rule_name = "".join(c for c in nfkd if not unicodedata.combining(c))
    if len(rule_name) > 64: rule_name = rule_name[:61] + "..."
    if rule_name: parts.append(f"rulename={format_nsrpc_param(rule_name)}")
    if comment: parts.append(f"comment={format_nsrpc_param(comment)}")

    if 'dstport' not in row or not row['dstport']:
        service_val = pick(row, CSV_ALIASES.get('service', ['service']))
        if service_val:
            row['dstport'] = service_val

    for csv_key, nsrpc_token in CSV_TO_NSRPC_MAP.items():
        if csv_key in ["rule_name", "comment", "action", "service"]: continue
        aliases = CSV_ALIASES.get(csv_key, [csv_key])
        value = pick(row, aliases)
        if value:
            if nsrpc_token == "ipproto" and "," in value:
                value = value.split(',')[0]
            parts.append(f"{nsrpc_token}={format_nsrpc_param(value)}")

    cmd = " ".join(parts)
    return (cmd, None) if len(cmd) <= MAX_NSRPC_LINE else (None, "ligne NSRPC générée trop longue")

# --- End of copied code ---

def find_missing_rules(source_rules, final_rules):
    final_rule_names = {rule['rule_name'] for rule in final_rules if 'rule_name' in rule}
    unique_source_rules = {rule['rule_name']: rule for rule in source_rules if 'rule_name' in rule}
    missing_rules = []
    for rule_name, rule_data in unique_source_rules.items():
        if rule_name not in final_rule_names:
            missing_rules.append(rule_data)
    return missing_rules

def write_commands_to_file(commands, filepath):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for command in commands:
                f.write(command + '\n')
    except IOError as e:
        print(f"Error writing to file {filepath}: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Compare Stormshield CSV rule exports and generate CLI commands for missing rules."
    )
    parser.add_argument(
        "--source", action="append", required=True,
        help="Path to a source CSV file. Can be specified multiple times.",
    )
    parser.add_argument(
        "--final", required=True,
        help="Path to the final CSV file to compare against.",
    )
    parser.add_argument(
        "--output", required=True,
        help="Path to the output file for the generated CLI commands.",
    )
    parser.add_argument(
        "--policy-index", type=int, default=9,
        help="The default policy index for the generated CLI commands (default: 9).",
    )
    args = parser.parse_args()

    print("Script execution started.")
    try:
        source_rules = []
        for source_file in args.source:
            source_rules.extend(read_csv(Path(source_file)))
        final_rules = read_csv(Path(args.final))
        print(f"Found {len(source_rules)} rules in source files.")
        print(f"Found {len(final_rules)} rules in final file.")
    except FileNotFoundError as e:
        print(f"Error: File not found - {e.filename}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while reading files: {e}", file=sys.stderr)
        sys.exit(1)

    missing_rules = find_missing_rules(source_rules, final_rules)
    print(f"Found {len(missing_rules)} missing rules to generate.")

    cli_commands = []
    for i, rule_data in enumerate(missing_rules, start=1):
        rtype = classify_row(rule_data)
        if rtype == "NAT":
            cmd, err = build_nat_cmd(rule_data, args.policy_index, i)
        else: # Default to FILTER
            cmd, err = build_filter_cmd(rule_data, args.policy_index, i)

        if cmd:
            cli_commands.append(cmd)
        else:
            rule_name = rule_data.get('rule_name', f'row {i}')
            print(f"Warning: Could not generate command for rule '{rule_name}'. Reason: {err}", file=sys.stderr)

    if cli_commands:
        write_commands_to_file(cli_commands, args.output)
        print(f"\nSuccessfully wrote {len(cli_commands)} CLI commands to {args.output}")
    else:
        print("\nNo missing rules found or generated. Output file was not created.")

    print("Script finished.")

if __name__ == "__main__":
    main()
