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
from pathlib import Path
from typing import Dict, List, Tuple, Optional

MAX_NSRPC_LINE = 512
ALLOWED_ACTIONS = {"pass", "block", "drop", "bypass"}

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
    """
    Parses a file containing object names.
    It accepts both the raw 'CONFIG OBJECT LIST' output (looking for 'name="..."')
    and simple text files with one object name per line.
    """
    if not file_path or not file_path.exists():
        return set()

    names = set()
    name_re = re.compile(r'name="([^"]+)"')
    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            match = name_re.search(line)
            if match:
                # Handle 'name="..."' format from command output
                names.add(match.group(1))
            else:
                # Handle plain name format, ignoring comments and empty lines
                clean_line = line.strip()
                if clean_line and not clean_line.startswith('#'):
                    names.add(clean_line)
    print(f"[INFO] Loaded {len(names)} existing objects.")
    return names

def parse_interfaces_file(file_path: Optional[Path]) -> set[str]:
    """
    Parses a file containing interface names. It handles multiple formats:
    - Raw 'CONFIG NETWORK INTERFACE SHOW' output (looks for 'ifname=...').
    - Multi-line INI-style blocks (looks for 'Name="..."').
    - Simple text files with one interface name per line.
    """
    if not file_path or not file_path.exists():
        return set()

    names = set()
    ifname_re = re.compile(r'ifname=("[^"]+"|\S+)')
    name_re = re.compile(r'Name="([^"]+)"')  # For INI-style format

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

            # Fallback to plain name format, ignoring comments and INI-style artifacts.
            if clean_line and not clean_line.startswith(('#', '[')) and '=' not in clean_line:
                names.add(clean_line)

    print(f"[INFO] Loaded {len(names)} existing interfaces.")
    return names

def read_csv(path: Path) -> List[Dict[str, str]]:
    """
    Reads a CSV file, expecting a header row to define the columns.
    The header row can optionally start with a '#' character.
    """
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        all_lines = f.readlines()

    # Find the header line and index
    header_line_content = None
    header_line_index = -1
    for i, line in enumerate(all_lines):
        stripped = line.strip()
        if stripped:
            # The first non-empty line is assumed to be the header
            header_line_content = stripped.lstrip('#') # Remove '#' if present
            header_line_index = i
            break

    if header_line_content is None:
        return [] # File is empty

    # Data lines are all non-empty lines after the header
    data_lines = [line for line in all_lines[header_line_index + 1:] if line.strip()]

    # --- Robust header-based parser ---
    import io
    delim = ';' if ';' in header_line_content else ','

    # Parse the header
    original_headers = next(csv.reader([header_line_content], delimiter=delim))

    # Clean headers: strip whitespace/quotes, remove leading '#', and handle potential duplicates
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

    # Process the data lines
    final_rows = []
    reader = csv.reader(data_lines, delimiter=delim)
    for fields in reader:
        if not any(field.strip() for field in fields):  # Skip rows with only empty/whitespace fields
            continue

        padded_fields = fields + [""] * (len(cleaned_headers) - len(fields))
        row_dict = dict(zip(cleaned_headers, padded_fields[:len(cleaned_headers)]))

        # Clean values: strip whitespace and quotes
        for key, value in row_dict.items():
            row_dict[key] = value.strip().strip('"') if value is not None else ""
        final_rows.append(row_dict)

    return final_rows

def is_valid_host_ip(s: str) -> bool:
    """
    Validates if a string is a single, valid IPv4 address.
    Returns False for networks, ranges, or non-IP strings.
    """
    ip_re = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
    return bool(ip_re.match(s))

def generate_host_objects(rows: List[Dict[str, str]]) -> Tuple[List[str], set]:
    """
    Scans rows for unique IP addresses and generates host object creation commands.
    """
    unique_ips = set()
    # Define groups of aliases for each potential IP field
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
        # Sort for consistent output
        for ip in sorted(list(unique_ips)):
            object_name = f"H_{ip.replace('.', '_')}"
            commands.append(f'CONFIG OBJECT HOST NEW name={object_name} ip={ip} comment=""')
        commands.append("")  # Add a blank line for readability
    return commands, unique_ips

def is_valid_ip_or_network(s: str) -> bool:
    """
    Validates if a string is a valid IPv4 address, a CIDR network, or an IP range.
    """
    # Regex for IPv4 address
    ip_re = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
    # Regex for CIDR network
    cidr_re = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)/(?:[0-2]?\d|3[0-2])$")
    # Regex for IP range
    range_re = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)-(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")

    return bool(ip_re.match(s) or cidr_re.match(s) or range_re.match(s))

def format_nsrpc_param(value: str) -> str:
    """
    Correctly formats a value for an NSRPC command parameter.
    - It leaves simple values (IPs, 'any', object names without spaces) unquoted.
    - It quotes values that contain spaces or special characters.
    - It strips accents from all values.
    - It escapes internal quotes within a value that needs to be quoted.
    """
    # Normalize and strip accents first
    nfkd = unicodedata.normalize("NFKD", value)
    clean_val = "".join(c for c in nfkd if not unicodedata.combining(c)).strip()

    if not clean_val:
        return '""'

    # A "simple" value does not need quotes. This includes IPs, 'any', and object
    # names that don't contain spaces or other shell-sensitive characters.
    # We define simple as alphanumeric plus underscore, dot, and hyphen.
    is_simple = re.match(r'^[a-zA-Z0-9_.-]+$', clean_val) is not None

    if clean_val.lower() == 'any' or is_valid_ip_or_network(clean_val) or is_simple:
        return clean_val
    else:
        # If the value is not simple, it must be quoted.
        # Any pre-existing double quotes inside the string must be escaped.
        return f'"{clean_val.replace("\"", r"\"")}"'

def classify_row(row: Dict[str, str]) -> str:
    type_slot = pick(row, ["type_slot"])
    if type_slot == "local_nat_slot":
        return "NAT"
    if type_slot == "local_filter_slot":
        return "FILTER"
    if pick(row, ["action"]).lower() == "nat":
        return "NAT"
    if pick(row, ["nat_from_target"]) or pick(row, ["nat_to_target"]):
        return "NAT"
    return "FILTER"

def pick(row: Dict[str, str], keys: List[str]) -> str:
    for k in keys:
        if k in row:
            v = row.get(k, "").strip()
            if v:
                return v
    return ""

def normalize_placeholder(s: str) -> str:
    return s if s else "any"

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
    """
    Checks a rule's dependencies (objects, interfaces) against known lists.
    Returns a list of missing dependencies as (TYPE, NAME) tuples.
    """
    missing = []
    # Per user feedback, interfaces can be used in object fields (e.g. from_src).
    # Therefore, we create a combined set of all known names for checking object fields.
    all_known_names = known_objects.union(known_interfaces, {f"H_{ip.replace('.', '_')}" for ip in created_host_ips})

    # Object fields to check
    fields = [
        ("OBJECT", ["from_src", "source"]),
        ("OBJECT", ["to_dest", "destination"]),
        ("OBJECT", ["service", "to_port", "dstport"]),
        ("OBJECT", ["nat_from_target", "natsrctarget"]),
        ("OBJECT", ["nat_to_target", "natdsttarget"]),
        ("OBJECT", ["nat_to_port", "natdstport"]),
    ]
    for dep_type, aliases in fields:
        val = pick(row, aliases)
        # A value can be a single object or a comma-separated list of objects.
        if val and val.lower() != 'any' and not is_valid_ip_or_network(val):
            object_names = [name.strip() for name in val.split(',')]
            for name in object_names:
                if name and name not in all_known_names:
                    missing.append((dep_type, name))

    # Interface fields to check (these should only contain interfaces)
    if_fields = [("INTERFACE", ["from_if"]), ("INTERFACE", ["to_if"])]
    for dep_type, aliases in if_fields:
        val = pick(row, aliases)
        # A value can be a single interface or a comma-separated list.
        if val and val.lower() != 'any':
            if_names = [name.strip() for name in val.split(',')]
            for name in if_names:
                if name and name not in known_interfaces:
                    missing.append((dep_type, name))

    return list(set(missing))


def build_filter_cmd(row: Dict[str, str], prefix: str, default_slot: int, position: int, created_host_ips: set = None) -> Tuple[Optional[str], Optional[str]]:
    if created_host_ips is None: created_host_ips = set()

    srctarget = normalize_placeholder(pick(row, ["from_src", "source"]))
    dsttarget = normalize_placeholder(pick(row, ["to_dest", "destination"]))
    dstport = normalize_placeholder(pick(row, ["to_port", "service", "dstport"]))
    action_raw = pick(row, ["action"])

    if not all([srctarget, dsttarget, dstport, action_raw]):
        return None, "champ essentiel manquant (srctarget, dsttarget, dstport, ou action)"

    if srctarget in created_host_ips: srctarget = f"H_{srctarget.replace('.', '_')}"
    if dsttarget in created_host_ips: dsttarget = f"H_{dsttarget.replace('.', '_')}"

    action = coerce_action(action_raw)
    if not action: return None, f"action inconnue: {action_raw!r}"

    rule_name = pick(row, ["rule_name"])
    comment = pick(row, ["comment"])

    # If rule_name is not present, use comment as name, or generate a default one.
    if not rule_name:
        rule_name = comment if comment else f"Rule-{position:04d}"
        # If the comment was used as the name, clear the comment to avoid duplication.
        if rule_name == comment:
            comment = ""

    # Add prefix if provided
    if prefix:
        rule_name = f"{prefix}{rule_name}"

    # Sanitize and truncate rule name
    rule_name = rule_name.replace("\n", " ").strip()
    if len(rule_name) > 64:
        rule_name = rule_name[:61] + "..."
    nfkd = unicodedata.normalize("NFKD", rule_name)
    rule_name = "".join(c for c in nfkd if not unicodedata.combining(c))

    slot_str = pick(row, ["policy", "slot", "index"])
    slot = int(slot_str) if slot_str.isdigit() else default_slot

    parts = [
        "CONFIG FILTER RULE INSERT", f"index={slot}", "type=filter", "state=on",
        f"action={action}", f"srctarget={format_nsrpc_param(srctarget)}",
        f"dsttarget={format_nsrpc_param(dsttarget)}", f"dstport={format_nsrpc_param(dstport)}",
        f"position={position}", "loglevel=minor",
    ]

    # Add name and comment to parts
    parts.append(f"rulename={format_nsrpc_param(rule_name)}")
    if comment:
        parts.append(f"comment={format_nsrpc_param(comment)}")

    cmd = " ".join(parts)
    return (cmd, None) if len(cmd) <= MAX_NSRPC_LINE else (None, "ligne NSRPC trop longue")

def build_nat_cmd(row: Dict[str, str], prefix: str, default_slot: int, position: int, created_host_ips: set = None) -> Tuple[Optional[str], Optional[str]]:
    if created_host_ips is None: created_host_ips = set()

    srctarget = normalize_placeholder(pick(row, ["from_src", "source"]))
    dsttarget = normalize_placeholder(pick(row, ["to_dest", "destination"]))
    dstport = normalize_placeholder(pick(row, ["to_port", "service", "dstport"]))
    natsrctarget = pick(row, ["nat_from_target", "natsrctarget"])
    natdsttarget = pick(row, ["nat_to_target", "natdsttarget"])
    natdstport = pick(row, ["nat_to_port", "natdstport"])

    if not all([srctarget, dsttarget, dstport]): return None, "champ NAT essentiel manquant"
    if not (natsrctarget or natdsttarget): return None, "destination de la translation manquante"

    if srctarget in created_host_ips: srctarget = f"H_{srctarget.replace('.', '_')}"
    if dsttarget in created_host_ips: dsttarget = f"H_{dsttarget.replace('.', '_')}"
    if natsrctarget in created_host_ips: natsrctarget = f"H_{natsrctarget.replace('.', '_')}"
    if natdsttarget in created_host_ips: natdsttarget = f"H_{natdsttarget.replace('.', '_')}"

    slot_str = pick(row, ["policy", "slot", "index"])
    slot = int(slot_str) if slot_str.isdigit() else default_slot

    rule_name = pick(row, ["rule_name"])
    comment = pick(row, ["comment"])

    # If rule_name is not present, use comment as name, or generate a default one.
    if not rule_name:
        rule_name = comment if comment else f"Rule-{position:04d}"
        # If the comment was used as the name, clear the comment to avoid duplication.
        if rule_name == comment:
            comment = ""

    # Add prefix if provided
    if prefix:
        rule_name = f"{prefix}{rule_name}"

    # Sanitize and truncate rule name
    rule_name = rule_name.replace("\n", " ").strip()
    if len(rule_name) > 64:
        rule_name = rule_name[:61] + "..."
    nfkd = unicodedata.normalize("NFKD", rule_name)
    rule_name = "".join(c for c in nfkd if not unicodedata.combining(c))

    parts = [
        "CONFIG FILTER RULE INSERT", f"index={slot}", "type=nat", "state=on", "action=nat",
        f"srctarget={format_nsrpc_param(srctarget)}", f"dsttarget={format_nsrpc_param(dsttarget)}",
        f"dstport={format_nsrpc_param(dstport)}", f"position={position}",
    ]
    if natsrctarget: parts.append(f"natsrctarget={format_nsrpc_param(natsrctarget)}")
    if natdsttarget: parts.append(f"natdsttarget={format_nsrpc_param(natdsttarget)}")
    if natdstport: parts.append(f"natdstport={format_nsrpc_param(natdstport)}")

    # Add name and comment to parts
    parts.append(f"rulename={format_nsrpc_param(rule_name)}")
    if comment:
        parts.append(f"comment={format_nsrpc_param(comment)}")

    cmd = " ".join(parts)
    return (cmd, None) if len(cmd) <= MAX_NSRPC_LINE else (None, "ligne NSRPC trop longue")

def mask_ips(text: str) -> str:
    ip_re = re.compile(r"\b(\d{1,3})\.\d{1,3}\.\d{1,3}\.(\d{1,3})\b")
    return ip_re.sub(r"\1.x.x.\2", text)

def write_safe_rules_file(out_path: Path, cmd_list: List[str], source_csv_paths: List[str], activate: bool, slot: int, group_by_10: bool = False) -> None:
    header = [
        f"# NSRPC generated on {datetime.datetime.now().isoformat(timespec='seconds')}",
        f"# Source CSVs: {', '.join(source_csv_paths)}",
        f"# Number of commands: {len(cmd_list)}",
        "SYSTEM SESSION language=fr",
        "MODIFY ON FORCE",
        f"CONFIG SLOT ACTIVATE type=filter slot={slot}",
    ]
    with out_path.open("w", encoding="utf-8", newline="") as f:
        f.write("\n".join(header) + "\n")
        rule_count = 0
        for cmd in cmd_list:
            f.write(cmd + "\n")
            if cmd.strip() and not cmd.strip().startswith("#"):
                rule_count += 1
                if group_by_10 and rule_count > 0 and rule_count % 10 == 0:
                    f.write("\n")
        if activate:
            f.write("CONFIG FILTER ACTIVATE\n")


def write_pending_rules_file(out_path: Path, pending_rules: List[str]):
    """
    Writes the pending rules to a file.
    These are generated as complete, uncommented NSRPC commands but are expected to fail.
    """
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
    """Writes the missing dependencies to a file in TYPE:NAME format."""
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

    # Create output directory if it doesn't exist
    out_dir = Path(args.output_directory)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load known objects and interfaces for validation
    known_objects = parse_objects_file(Path(args.objects_file) if args.objects_file else None)
    known_interfaces = parse_interfaces_file(Path(args.interfaces_file) if args.interfaces_file else None)

    all_rows = []
    total_lines_read = 0
    for csv_path_str in args.csv:
        in_path = Path(csv_path_str)
        if not in_path.exists():
            print(f"[ERROR] CSV introuvable: {in_path}", file=sys.stderr)
            continue
        try:
            rows = read_csv(in_path)
            all_rows.extend(rows)
            total_lines_read += len(rows)
            print(f"[INFO] Lu {len(rows)} lignes depuis {in_path}")
        except Exception as e:
            print(f"[ERROR] Lecture CSV échouée pour {in_path}: {e}", file=sys.stderr)
            continue

    safe_commands: List[str] = []
    pending_rules: List[str] = []
    all_missing_dependencies = set()
    num_pending_rules = 0

    created_host_ips = set()
    if args.create_hosts:
        print("[INFO] Analysing IP addresses for Host object creation...")
        host_commands, created_host_ips = generate_host_objects(all_rows)
        safe_commands.extend(host_commands)
        if host_commands:
            print(f"[INFO] {len(created_host_ips)} unique Host objects will be created.")

    # Process rules
    current_position = args.start_position
    for i, row in enumerate(all_rows):
        # Skip separators or empty-like rows
        if not pick(row, ["action", "from_src", "to_dest"]):
            continue

        # Find missing dependencies
        missing = find_missing_dependencies(row, known_objects, known_interfaces, created_host_ips)

        if not missing:
            # Rule is valid, build the command
            rtype = classify_row(row)
            cmd, err = (build_nat_cmd(row, args.prefix, args.slot, current_position, created_host_ips)
                        if rtype == "NAT"
                        else build_filter_cmd(row, args.prefix, args.slot, current_position, created_host_ips))

            if cmd:
                safe_commands.append(cmd)
                current_position += 1
            else:
                # This rule is invalid for a reason other than missing dependency
                num_pending_rules += 1
                reason = f"Could not build command: {err or 'unknown error'}"
                pending_rules.append(f"# Ignored rule from row {i+1}: {reason}")
                pending_rules.append(f"# Data: {row}")
                pending_rules.append("")

        else:
            # Rule is pending due to missing dependencies
            num_pending_rules += 1
            all_missing_dependencies.update(missing)
            reasons = ", ".join([f"{t}:{n}" for t, n in sorted(list(missing))])

            # Attempt to build the command anyway to have it in CLI format
            rtype = classify_row(row)
            cmd, err = (build_nat_cmd(row, args.prefix, args.slot, current_position, created_host_ips)
                        if rtype == "NAT"
                        else build_filter_cmd(row, args.prefix, args.slot, current_position, created_host_ips))

            if cmd:
                # Add a comment with the reason, then the uncommented command
                pending_rules.append(f"# PENDING: Missing dependencies: {reasons}")
                pending_rules.append(cmd)
                pending_rules.append("")
            else:
                # Fallback if command can't be built at all
                pending_rules.append(f"# PENDING: Rule from row {i+1} has missing dependencies AND could not be built.")
                pending_rules.append(f"# Missing: {reasons}")
                pending_rules.append(f"# Build error: {err or 'unknown'}")
                pending_rules.append(f"# Original data: {row}")
                pending_rules.append("")

    # --- Write output files ---
    try:
        write_safe_rules_file(args.out_safe, safe_commands, args.csv, args.activate, args.slot, args.group_by_10)
        if pending_rules:
            write_pending_rules_file(args.out_pending, pending_rules)
        if all_missing_dependencies:
            write_missing_dependencies_file(args.out_missing, all_missing_dependencies)
    except Exception as e:
        print(f"[ERROR] Failed to write output files: {e}", file=sys.stderr)
        return 3

    # --- Final summary ---
    num_safe_rules = len([c for c in safe_commands if c.strip() and not c.strip().startswith("#")])

    summary = (
        f"\n[INFO] Processing complete.\n"
        f"  - Total lines read from CSV: {total_lines_read}\n"
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
