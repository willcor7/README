#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stormshield CSV (local_filter, ...) -> NSRPC commands converter.
Portable: Python 3.8+, stdlib only.

This script converts a Stormshield CSV export file into a set of NSRPC commands.
It provides a validation mechanism to ensure that all objects (hosts, services, etc.)
and interfaces used in the rules exist on the target firewall.

The script generates three output files:
1.  rules_safe.txt: Contains NSRPC commands for rules that passed validation.
2.  rules_pending.txt: Contains original data for rules that failed validation
    due to missing dependencies.
3.  dependencies_missing.txt: A list of all unique objects and interfaces that
    were not found.

This allows for a safer application of firewall rules by identifying
missing prerequisites beforehand.
"""

import argparse
import csv
import datetime
import re
import sys
import unicodedata
from itertools import zip_longest
from pathlib import Path
from typing import Dict, List, Tuple, Optional

MAX_NSRPC_LINE = 1024  # Increased for potentially longer commands
ALLOWED_ACTIONS = {"pass", "block", "drop", "bypass", "deleg", "reset", "log", "decrypt", "nat"}

CSV_TO_NSRPC_MAP = {
    # Maps CSV header names to their corresponding NSRPC command tokens.
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
    # Provides alternative CSV header names for common fields.
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


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=("Convert a Stormshield CSV export (local_filter, ...) "
                     "into a NSRPC command script with dependency validation."))

    # --- Input files ---
    inputs = p.add_argument_group('Input Files')
    inputs.add_argument("--csv", required=True, nargs='+', help="Input CSV path(s). Can specify multiple files.")

    # --- Output files ---
    outputs = p.add_argument_group('Output Files')
    outputs.add_argument("--output-directory", default=".", help="Directory to store output files.")

    # --- Validation files ---
    validation = p.add_argument_group('Validation Files')
    validation.add_argument("--objects-file", default=None, help="Path to a file containing existing object names (output of 'CONFIG OBJECT LIST').")
    validation.add_argument("--interfaces-file", default=None, help="Path to a file containing existing interface names (output of 'CONFIG NETWORK INTERFACE SHOW').")

    # --- Rule generation options ---
    rules = p.add_argument_group('Rule Generation Options')
    rules.add_argument("--prefix", default="", help="Prefix to prepend to rule names")
    rules.add_argument("--slot", type=int, default=9, help="Default filter policy slot (index) number")
    rules.add_argument("--start-position", type=int, default=1, help="Starting position for the rules to be added")
    rules.add_argument("--create-hosts", action="store_true",
                   help="Create host objects for unique IPs and use them in rules.")

    # --- Script behavior ---
    behavior = p.add_argument_group('Script Behavior')
    behavior.add_argument("--activate", action="store_true",
                   help="Append 'CONFIG FILTER ACTIVATE' at the end of the safe rules file.")
    behavior.add_argument("--mask", action="store_true",
                   help="Mask IP-like patterns in console logs.")
    behavior.add_argument("--log", default=None,
                   help="Optional log file path (errors only).")
    behavior.add_argument("--group-by-10", action="store_true",
                   help="Add a blank line every 10 rules for readability in the safe rules file.")

    args = p.parse_args()

    # Define output file paths based on the output directory
    out_dir = Path(args.output_directory)
    args.out_safe = out_dir / "rules_safe.txt"
    args.out_pending = out_dir / "rules_pending.txt"
    args.out_missing = out_dir / "dependencies_missing.txt"

    return args

def parse_objects_file(file_path: Optional[Path]) -> set[str]:
    if not file_path or not file_path.exists():
        return set()
    names = set()
    name_re = re.compile(r'name="([^"]+)"')
    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            match = name_re.search(line)
            if match:
                names.add(match.group(1))
            else:
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'):
                    names.add(clean_line)
    print(f"[INFO] Loaded {len(names)} existing objects.")
    return names

def parse_interfaces_file(file_path: Optional[Path]) -> set[str]:
    if not file_path or not file_path.exists():
        return set()
    names = set()
    ifname_re = re.compile(r'ifname=("[^"]+"|\S+)')
    name_re = re.compile(r'Name="([^"]+)"')
    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            clean_line = line.strip()
            ifname_match = ifname_re.search(clean_line)
            if ifname_match:
                names.add(ifname_match.group(1).strip('"'))
                continue
            name_match = name_re.search(clean_line)
            if name_match:
                names.add(name_match.group(1))
                continue
            if clean_line and not clean_line.startswith(('#', '[')) and '=' not in clean_line:
                names.add(clean_line)
    print(f"[INFO] Loaded {len(names)} existing interfaces.")
    return names

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
    import io
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

def is_valid_host_ip(s: str) -> bool:
    ip_re = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
    return bool(ip_re.match(s))

def generate_host_objects(rows: List[Dict[str, str]]) -> Tuple[List[str], set]:
    unique_ips = set()
    source_aliases = ["from_src", "source_ip", "src", "source", "src_ip"]
    dest_aliases = ["to_dest", "destination_ip", "dest_ip", "dst_ip", "destination"]
    natsrc_aliases = ["nat_from_target", "natsrctarget", "src_translation", "to_src"]
    natdest_aliases = ["nat_to_target", "natdsttarget", "dst_translation", "to_dst", "translated_ip", "to"]
    for row in rows:
        for aliases in [source_aliases, dest_aliases, natsrc_aliases, natdest_aliases]:
            ip_value = pick(row, aliases)
            if is_valid_host_ip(ip_value):
                unique_ips.add(ip_value)
    commands = []
    if unique_ips:
        commands.append("# --- Objets Hôtes ---")
        for ip in sorted(list(unique_ips)):
            object_name = f"H_{ip.replace('.', '_')}"
            commands.append(f'CONFIG OBJECT HOST NEW name={object_name} ip={ip} comment=""')
        commands.append("")
    return commands, unique_ips

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

def pick(row: Dict[str, str], keys: List[str]) -> str:
    for k in keys:
        if k in row:
            v = row.get(k, "").strip()
            if v:
                return v
    return ""

def coerce_action(val: str) -> Optional[str]:
    v = (val or "").strip().lower()
    if v in ALLOWED_ACTIONS:
        return v
    mapping = {"allow": "pass", "accept": "pass", "deny": "drop"}
    return mapping.get(v)

def find_missing_dependencies(
    row: Dict[str, str],
    known_objects: set[str],
    known_interfaces: set[str],
    created_host_ips: set[str]
) -> List[Tuple[str, str]]:
    missing = []
    all_known_names = known_objects.union(known_interfaces, {f"H_{ip.replace('.', '_')}" for ip in created_host_ips})
    object_fields = [
        "from_src", "to_dest", "service", "nat_from_target", "nat_to_target",
        "nat_to_port", "schedule", "route", "from_geo", "to_geo",
        "from_ip_rep", "to_ip_rep"
    ]
    for field in object_fields:
        aliases = CSV_ALIASES.get(field, [field])
        val = pick(row, aliases)
        if val and val.lower() != 'any' and not is_valid_ip_or_network(val):
            object_names = [name.strip() for name in val.split(',')]
            for name in object_names:
                if name and name not in all_known_names:
                    missing.append(("OBJECT", name))
    if_fields = ["from_if", "to_if"]
    for field in if_fields:
        val = pick(row, [field])
        if val and val.lower() != 'any':
            if_names = [name.strip() for name in val.split(',')]
            for name in if_names:
                if name and name not in known_interfaces:
                    missing.append(("INTERFACE", name))
    return list(set(missing))

def classify_row(row: Dict[str, str]) -> str:
    """Determines if a rule is FILTER or NAT."""
    type_slot = pick(row, ["type_slot"])
    if "nat" in type_slot.lower():
        return "NAT"
    # Fallback for older formats or rows without type_slot
    if pick(row, ["action"]).lower() == "nat":
        return "NAT"
    if pick(row, ["nat_from_target"]) or pick(row, ["nat_to_target"]):
        return "NAT"
    return "FILTER"

def build_filter_cmd(row: Dict[str, str], prefix: str, default_slot: int, position: int, created_host_ips: set = None) -> Tuple[Optional[str], Optional[str]]:
    if created_host_ips is None: created_host_ips = set()
    parts = ["CONFIG FILTER RULE INSERT"]

    slot_str = pick(row, ["policy", "slot", "index"])
    slot = int(slot_str) if slot_str.isdigit() else default_slot
    parts.extend([f"index={slot}", "type=filter", f"position={position}"])

    rule_name = pick(row, CSV_ALIASES.get("rule_name", ["rule_name"]))
    comment = pick(row, CSV_ALIASES.get("comment", ["comment"]))
    if not rule_name:
        rule_name = comment if comment else f"FilterRule-{position:04d}"
        if rule_name == comment: comment = ""
    if prefix:
        rule_name = f"{prefix}{rule_name}"

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
            if nsrpc_token in ["srctarget", "dsttarget"] and value in created_host_ips:
                value = f"H_{value.replace('.', '_')}"
            if nsrpc_token == "action":
                value = coerce_action(value)
                if not value: return None, f"action de filtre inconnue: {pick(row, aliases)!r}"
            if nsrpc_token == "ipproto" and "," in value:
                value = value.split(',')[0]
            parts.append(f"{nsrpc_token}={format_nsrpc_param(value)}")

    cmd = " ".join(parts)
    return (cmd, None) if len(cmd) <= MAX_NSRPC_LINE else (None, "ligne NSRPC générée trop longue")

def build_nat_cmd(row: Dict[str, str], prefix: str, default_slot: int, position: int, created_host_ips: set = None) -> Tuple[Optional[str], Optional[str]]:
    if created_host_ips is None: created_host_ips = set()
    parts = ["CONFIG FILTER RULE INSERT"]

    slot_str = pick(row, ["policy", "slot", "index"])
    slot = int(slot_str) if slot_str.isdigit() else default_slot
    parts.extend([f"index={slot}", "type=nat", "action=nat", f"position={position}"])

    rule_name = pick(row, CSV_ALIASES.get("rule_name", ["rule_name"]))
    comment = pick(row, CSV_ALIASES.get("comment", ["comment"]))
    if not rule_name:
        rule_name = comment if comment else f"NatRule-{position:04d}"
        if rule_name == comment: comment = ""
    if prefix:
        rule_name = f"{prefix}{rule_name}"

    nfkd = unicodedata.normalize("NFKD", rule_name.replace("\n", " ").strip())
    rule_name = "".join(c for c in nfkd if not unicodedata.combining(c))
    if len(rule_name) > 64: rule_name = rule_name[:61] + "..."
    if rule_name: parts.append(f"rulename={format_nsrpc_param(rule_name)}")
    if comment: parts.append(f"comment={format_nsrpc_param(comment)}")

    # Handle port mapping: service -> dstport for NAT rules
    if 'dstport' not in row or not row['dstport']:
        service_val = pick(row, CSV_ALIASES.get('service', ['service']))
        if service_val:
            row['dstport'] = service_val

    for csv_key, nsrpc_token in CSV_TO_NSRPC_MAP.items():
        if csv_key in ["rule_name", "comment", "action", "service"]: continue
        aliases = CSV_ALIASES.get(csv_key, [csv_key])
        value = pick(row, aliases)
        if value:
            if nsrpc_token in ["srctarget", "dsttarget", "natsrctarget", "natdsttarget"] and value in created_host_ips:
                value = f"H_{value.replace('.', '_')}"
            if nsrpc_token == "ipproto" and "," in value:
                value = value.split(',')[0]
            parts.append(f"{nsrpc_token}={format_nsrpc_param(value)}")

    cmd = " ".join(parts)
    return (cmd, None) if len(cmd) <= MAX_NSRPC_LINE else (None, "ligne NSRPC générée trop longue")

def mask_ips(text: str) -> str:
    ip_re = re.compile(r"\b(\d{1,3})\.\d{1,3}\.\d{1,3}\.(\d{1,3})\b")
    return ip_re.sub(r"\1.x.x.\2", text)

def write_safe_rules_file(out_path: Path, cmd_list: List[str], source_csv_paths: List[str], activate: bool, slot: int, group_by_10: bool = False) -> None:
    header = [
        f"# NSRPC generated on {datetime.datetime.now().isoformat(timespec='seconds')}",
        f"# Source CSVs: {', '.join(map(str, source_csv_paths))}",
        f"# Number of commands: {len(cmd_list)}",
        "SYSTEM SESSION language=fr",
        "MODIFY ON FORCE",
        f"CONFIG SLOT ACTIVATE type=filter slot={slot}",
    ]
    with out_path.open("w", encoding="utf-8", newline="") as f:
        f.write("\n".join(header) + "\n\n")
        rule_count = 0
        for cmd in cmd_list:
            f.write(cmd + "\n")
            if cmd.strip() and not cmd.strip().startswith("#"):
                rule_count += 1
                if group_by_10 and rule_count > 0 and rule_count % 10 == 0:
                    f.write("\n")
        if activate:
            f.write("\nCONFIG FILTER ACTIVATE\n")

def write_pending_rules_file(out_path: Path, pending_rules: List[str]):
    warning_header = [
        "######################################################################",
        "# WARNING: PENDING RULES                                           #",
        "# ------------------------------------------------------------------ #",
        "# The commands in this file have MISSING DEPENDENCIES.               #",
        "# They are provided for debugging purposes and are LIKELY TO FAIL if #",
        "# executed directly on a firewall without first creating the       #",
        "# missing objects or interfaces.                                     #",
        "######################################################################",
        f"\n# Generated on: {datetime.datetime.now().isoformat(timespec='seconds')}\n"
    ]
    with out_path.open("w", encoding="utf-8") as f:
        f.write("\n".join(warning_header))
        f.write("\n".join(pending_rules))

def write_missing_dependencies_file(out_path: Path, missing_deps: set):
    header = f"# Missing dependencies found on {datetime.datetime.now().isoformat(timespec='seconds')}"
    with out_path.open("w", encoding="utf-8") as f:
        f.write(header + "\n\n")
        if not missing_deps:
            f.write("# No missing dependencies were found.\n")
        else:
            for dep_type, name in sorted(list(missing_deps)):
                f.write(f"{dep_type}: {name}\n")

def main() -> int:
    args = parse_args()
    out_dir = Path(args.output_directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    known_objects = parse_objects_file(Path(args.objects_file) if args.objects_file else None)
    known_interfaces = parse_interfaces_file(Path(args.interfaces_file) if args.interfaces_file else None)

    # --- New Interleaved Reading Logic ---
    list_of_row_lists = []
    for csv_path_str in args.csv:
        in_path = Path(csv_path_str)
        if not in_path.exists():
            print(f"[ERROR] CSV introuvable: {in_path}", file=sys.stderr)
            continue
        try:
            rows = read_csv(in_path)
            list_of_row_lists.append(rows)
            print(f"[INFO] Lu {len(rows)} lignes depuis {in_path}")
        except Exception as e:
            print(f"[ERROR] Lecture CSV échouée pour {in_path}: {e}", file=sys.stderr)
            continue

    # Interleave the rows from all files
    all_rows = []
    for row_tuple in zip_longest(*list_of_row_lists, fillvalue=None):
        for row in row_tuple:
            if row is not None:
                all_rows.append(row)

    # --- The rest of the processing logic remains the same ---
    safe_commands, pending_rules, all_missing_dependencies = [], [], set()
    num_pending_rules = 0
    created_host_ips = set()
    if args.create_hosts:
        print("[INFO] Analysing IP addresses for Host object creation...")
        host_commands, created_host_ips = generate_host_objects(all_rows)
        safe_commands.extend(host_commands)
        if host_commands:
            print(f"[INFO] {len(created_host_ips)} unique Host objects will be created.")
    current_position = args.start_position
    for i, row in enumerate(all_rows):
        if pick(row, ["separator_color"]): # Ignore visual separators from SMC
            continue

        # Determine rule type and call the appropriate builder
        rtype = classify_row(row)
        if rtype == "NAT":
            cmd, err = build_nat_cmd(row, args.prefix, args.slot, current_position, created_host_ips)
        else: # Default to FILTER
            cmd, err = build_filter_cmd(row, args.prefix, args.slot, current_position, created_host_ips)

        missing = find_missing_dependencies(row, known_objects, known_interfaces, created_host_ips)

        if not missing:
            if cmd:
                safe_commands.append(cmd)
                current_position += 1
            else:
                num_pending_rules += 1
                reason = f"Could not build command: {err or 'unknown error'}"
                pending_rules.extend([f"# Ignored rule from row {i+1}: {reason}", f"# Data: {row}", ""])
        else:
            num_pending_rules += 1
            all_missing_dependencies.update(missing)
            reasons = ", ".join([f"{t}:{n}" for t, n in sorted(list(missing))])
            if cmd:
                pending_rules.extend([f"# PENDING: Missing dependencies: {reasons}", cmd, ""])
            else:
                pending_rules.extend([f"# PENDING: Rule from row {i+1} has missing dependencies AND could not be built.",
                                      f"# Missing: {reasons}", f"# Build error: {err or 'unknown'}", f"# Original data: {row}", ""])
    try:
        write_safe_rules_file(args.out_safe, safe_commands, args.csv, args.activate, args.slot, args.group_by_10)
        if pending_rules:
            write_pending_rules_file(args.out_pending, pending_rules)
        if all_missing_dependencies:
            write_missing_dependencies_file(args.out_missing, all_missing_dependencies)
    except Exception as e:
        print(f"[ERROR] Failed to write output files: {e}", file=sys.stderr)
        return 3
    num_safe_rules = len([c for c in safe_commands if c.strip() and not c.strip().startswith("#")])
    summary = (
        f"\n[INFO] Processing complete.\n"
        f"  - Total lines read from CSV: {len(all_rows)}\n"
        f"  - Safe rules generated: {num_safe_rules}\n"
        f"  - Pending or ignored rules: {num_pending_rules}\n"
        f"  - Unique missing dependencies found: {len(all_missing_dependencies)}"
    )
    if args.mask:
        summary = mask_ips(summary)
    print(summary)
    print(f"\n[INFO] Safe rules file created: {args.out_safe}")
    if pending_rules:
        print(f"[INFO] Pending rules file created: {args.out_pending}")
    if all_missing_dependencies:
        print(f"[INFO] Missing dependencies file created: {args.out_missing}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
