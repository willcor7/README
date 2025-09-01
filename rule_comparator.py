import argparse
import csv
import sys

def main():
    """Main function to run the rule comparison."""
    parser = argparse.ArgumentParser(
        description="Compare Stormshield CSV rule exports and generate CLI commands for missing rules."
    )
    parser.add_argument(
        "--source",
        action="append",
        required=True,
        help="Path to a source CSV file. Can be specified multiple times.",
    )
    parser.add_argument(
        "--final",
        required=True,
        help="Path to the final CSV file to compare against.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to the output file for the generated CLI commands.",
    )
    parser.add_argument(
        "--policy-index",
        type=int,
        default=9,
        help="The policy index for the generated CLI commands (default: 9).",
    )
    parser.add_argument(
        "--loglevel",
        type=str,
        default="minor",
        help="The log level for the generated CLI commands (default: 'minor').",
    )

    args = parser.parse_args()

    print("Script execution started.")

    try:
        # Read rules from source files
        source_rules = []
        for source_file in args.source:
            source_rules.extend(read_rules_from_csv(source_file))

        # Read rules from the final file
        final_rules = read_rules_from_csv(args.final)

        print(f"Found {len(source_rules)} rules in source files.")
        print(f"Found {len(final_rules)} rules in final file.")

    except FileNotFoundError as e:
        print(f"Error: File not found - {e.filename}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    # Placeholder for future logic
    # Find missing rules
    missing_rules = find_missing_rules(source_rules, final_rules)
    print(f"Found {len(missing_rules)} missing rules.")

    # Generate CLI commands
    cli_commands = generate_cli_commands(
        missing_rules, args.policy_index, args.loglevel
    )

    # Write commands to output file
    if cli_commands:
        write_commands_to_file(cli_commands, args.output)
        print(f"\nSuccessfully wrote {len(cli_commands)} CLI commands to {args.output}")
    else:
        print("\nNo missing rules found. Output file was not created.")

    print("Script finished.")


def write_commands_to_file(commands, filepath):
    """Writes a list of commands to a file, one per line."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for command in commands:
                f.write(command + '\n')
    except IOError as e:
        print(f"Error writing to file {filepath}: {e}", file=sys.stderr)
        sys.exit(1)


def generate_cli_commands(rules, policy_index, loglevel):
    """Generates a list of Stormshield CLI commands from a list of rules."""
    commands = []
    for i, rule in enumerate(rules, start=1):
        command = (
            f'CONFIG FILTER RULE INSERT index={policy_index} type=filter '
            f'state={rule["state"]} action={rule["action"]} '
            f'srctarget={rule["from_src"]} dsttarget={rule["to_dest"]} '
            f'dstport={rule["to_port"]} position={i} loglevel={loglevel} '
            f'rulename={rule["rule_name"]} comment="{rule["comment"]}"'
        )
        commands.append(command)
    return commands


def find_missing_rules(source_rules, final_rules):
    """
    Compares source and final rules and returns a list of missing rules.

    A rule is considered missing if its 'rule_name' is in a source file
    but not in the final file. This function also handles deduplication
    of source rules.
    """
    final_rule_names = {rule['rule_name'] for rule in final_rules}

    # Use a dictionary to handle duplicates from source files; the last one wins.
    unique_source_rules = {rule['rule_name']: rule for rule in source_rules}

    missing_rules = []
    for rule_name, rule_data in unique_source_rules.items():
        if rule_name not in final_rule_names:
            missing_rules.append(rule_data)

    return missing_rules

def read_rules_from_csv(filepath):
    """
    Reads a Stormshield CSV file and returns a list of rule dictionaries.

    This function dynamically finds the header row (starting with '#') to map columns.
    """
    rules = []
    header_map = {}

    # These are the columns we need to extract from the CSV for the CLI command.
    required_fields = [
        "rule_name", "comment", "state", "action",
        "from_src", "to_dest", "to_port"
    ]

    with open(filepath, 'r', encoding='utf-8') as f:
        # Find header row and build column index map
        reader = csv.reader(f)
        for row in reader:
            if row and row[0].startswith('#'):
                header = [h.strip().lstrip('#') for h in row]
                try:
                    header_map = {field: header.index(field) for field in required_fields}
                except ValueError as e:
                    raise Exception(f"Missing required column in {filepath}: {e}")
                break # Header found, move to reading data

        if not header_map:
            raise Exception(f"Could not find a header row (starting with '#') in {filepath}")

        # Read the data rows
        for row in reader:
            if not row or not row[0]: # Skip empty or malformed rows
                continue

            rule_data = {}
            for field, index in header_map.items():
                try:
                    rule_data[field] = row[index]
                except IndexError:
                    # Handle rows that might be shorter than the header
                    print(f"Warning: Malformed row in {filepath}, skipping: {row}", file=sys.stderr)
                    rule_data = None
                    break

            if rule_data:
                rules.append(rule_data)

    return rules


if __name__ == "__main__":
    main()
