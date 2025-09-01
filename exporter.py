# -*- coding: utf-8 -*-
import argparse
import sys
import getpass
import time
import os
import re
from datetime import datetime

try:
    import paramiko
except ImportError:
    print("ERREUR CRITIQUE: La bibliothèque 'paramiko' n'est pas installée.", file=sys.stderr)
    print("Veuillez l'installer avec la commande : pip install paramiko", file=sys.stderr)
    sys.exit(1)

def execute_command_interactive(channel, command):
    """Exécute une commande dans un shell interactif et retourne la sortie."""
    channel.send(command + '\n')
    time.sleep(3)
    output = ""
    while channel.recv_ready():
        output += channel.recv(65535).decode('utf-8', errors='ignore')
    lines = output.splitlines()
    # Nettoyage pour enlever l'écho de la commande et le prompt
    return "\n".join(lines[1:-1]) if len(lines) > 2 else ""

def execute_commands_on_firewall(args):
    """Se connecte au pare-feu et exécute les commandes d'exportation."""
    client = None
    password = getpass.getpass(f"Veuillez entrer le mot de passe pour {args.user}@{args.host}: ")

    try:
        print(f"Connexion à {args.host} en tant que {args.user}...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=args.host, username=args.user, password=password, port=22, timeout=15)
        print("Connexion SSH initiale réussie.")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            print(f"Les fichiers seront sauvegardés dans : '{args.output_dir}'")

        def save_output(basename, content):
            filename = f"{args.output_prefix}_{basename}_{timestamp}.txt"
            filepath = os.path.join(args.output_dir, filename) if args.output_dir else filename
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"   -> Sortie enregistrée dans '{filepath}'")

        # --- Phase 1: Commandes 'sfctl' (non-interactives) ---
        if args.collect_sfctl:
            print("\n--- Collecte des données 'sfctl' ---")
            sfctl_commands = { "sfctl_route": "sfctl -s route", "sfctl_if": "sfctl -s if", "sfctl_ha": "sfctl -s ha", "sfctl_fpstat": "sfctl -s fpstat", "sfctl_rulestat": "sfctl -s rulestat" }
            for basename, cmd in sfctl_commands.items():
                print(f"-> Exécution de '{cmd}'...")
                stdin, stdout, stderr = client.exec_command(cmd, timeout=10)
                save_output(basename, stdout.read().decode('utf-8', errors='ignore'))

        # --- Phase 2: Commandes 'CONFIG' (interactives) ---
        print("\n--- Collecte des données 'CONFIG' ---")
        channel = client.invoke_shell()
        time.sleep(1); channel.recv(65535)
        channel.send('cli\n'); time.sleep(1)
        channel.send(password + '\n'); time.sleep(2); channel.recv(65535)
        print("Mode 'cli' activé.")

        # Commandes de base
        print("-> Export des objets et interfaces...")
        save_output("objects", execute_command_interactive(channel, "CONFIG OBJECT LIST type=all usage=any"))
        save_output("interfaces", execute_command_interactive(channel, "CONFIG NETWORK INTERFACE SHOW"))

        # Commandes optionnelles
        if args.collect_dhcp:
            print("-> Export des baux DHCP...")
            save_output("dhcp_hosts", execute_command_interactive(channel, "CONFIG DHCP HOST LIST"))
        if args.collect_snmp:
            print("-> Export de la configuration SNMP...")
            save_output("snmp_config", execute_command_interactive(channel, "CONFIG SNMP SHOW"))
        if args.collect_bird:
            print("-> Export de la configuration BIRD...")
            save_output("bird_config", execute_command_interactive(channel, "CONFIG BIRD SHOW"))

        # Logique "List-then-Show" pour IPsec
        if args.collect_ipsec:
            print("-> Export de la configuration IPsec...")
            peers_list_output = execute_command_interactive(channel, "CONFIG IPSEC PEER LIST")
            peer_names = [match.group(1) for match in re.finditer(r'name="([^"]*)"', peers_list_output)]
            for name in peer_names:
                save_output(f"ipsec_peer_{name}", execute_command_interactive(channel, f"CONFIG IPSEC PEER SHOW name={name}"))

            policies_list_output = execute_command_interactive(channel, "CONFIG IPSEC POLICY LIST")
            policy_names = [match.group(1) for match in re.finditer(r'name="([^"]*)"', policies_list_output)]
            for name in policy_names:
                save_output(f"ipsec_policy_{name}", execute_command_interactive(channel, f"CONFIG IPSEC POLICY SHOW name={name}"))

        channel.close()
        return True

    except Exception as e:
        print(f"Une erreur fatale est survenue : {e}", file=sys.stderr)
        return False
    finally:
        if client: client.close()
        print("\nConnexion SSH fermée.")

def main():
    parser = argparse.ArgumentParser(description="Exporte la configuration et l'état d'un pare-feu Stormshield via SSH.", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--host', required=True)
    parser.add_argument('--user', default='admin')
    parser.add_argument('--output-prefix', '-p', required=True)
    parser.add_argument('--output-dir', help="Dossier optionnel pour sauvegarder les fichiers.")
    parser.add_argument('--collect-sfctl', action='store_true')
    parser.add_argument('--collect-dhcp', action='store_true')
    parser.add_argument('--collect-snmp', action='store_true')
    parser.add_argument('--collect-ipsec', action='store_true')
    parser.add_argument('--collect-bird', action='store_true')

    args = parser.parse_args()

    if execute_commands_on_firewall(args):
        print("\nExportation terminée avec succès.")
    else:
        print("\nL'exportation a échoué.")
        sys.exit(1)

if __name__ == "__main__":
    main()
