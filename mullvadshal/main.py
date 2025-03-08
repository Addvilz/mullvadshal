import os
import json
import requests
import argparse
import codecs
import re
import random
import subprocess
import shutil
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

MULLVAD_SERVERS_URL = "https://api.mullvad.net/public/relays/wireguard/v2/"
IS_DEBUG = False


def run_command(command: str, error_message: str):
    """
    Run a shell command and handle errors properly.

    :param command: The shell command to execute.
    :param error_message: The message to include in the exception if the command fails.
    :return: The stdout output of the command.
    :raises RuntimeError: If the command execution fails.
    """
    try:
        result = subprocess.run(
            command, shell=True, check=True, capture_output=True, text=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"{error_message}: {e.stderr.strip() or e}") from e


def is_valid_interface_name(name: str) -> bool:
    """
    Validate a Linux network interface name.

    :param name: Network interface name as a string.
    :return: True if valid, False otherwise.
    """
    if not isinstance(name, str):
        return False

    if len(name) == 0 or len(name) > 15:
        return False

    # Match pattern: Starts with a letter, followed by allowed characters
    pattern = r"^[a-zA-Z][a-zA-Z0-9\-_\.]{0,14}$"
    return bool(re.match(pattern, name))


def wg_keypair() -> dict:
    x25519privkey = X25519PrivateKey.generate()

    privkey = x25519privkey.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    pubkey = x25519privkey.public_key()\
        .public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    return {
        'privkey': codecs.encode(privkey, 'base64').decode('utf8').strip(),
        'pubkey': codecs.encode(pubkey, 'base64').decode('utf8').strip(),
    }


def load_cfg(cfg_dir: str, iface: str) -> dict:
    cfg_file = f"{cfg_dir}/.mullvadshal-{iface}"

    if not os.access(cfg_dir, os.R_OK):
        raise PermissionError(f"Cannot read from {cfg_dir}")

    if os.path.exists(cfg_file) and not os.access(cfg_file, os.R_OK):
        raise PermissionError(f"Cannot read from {cfg_file}")

    cfg = {}

    if os.path.exists(cfg_file):
        with open(cfg_file, 'r') as f:
            try:
                cfg = json.load(f)
            except json.JSONDecodeError as e:
                if IS_DEBUG:
                    raise e

                raise ValueError(
                    f"Failed to parse config file: {cfg_file}, {e.msg}")

    if 'address' not in cfg:
        cfg['address'] = None

    if 'keypair' not in cfg:
        cfg['keypair'] = None

    if 'last-server' not in cfg:
        cfg['last-server'] = None

    if 'servers' not in cfg:
        cfg['servers'] = []

    return cfg


def save_cfg(cfg: dict, cfg_dir: str, iface: str):
    cfg_file = f"{cfg_dir}/.mullvadshal-{iface}"

    if not os.access(cfg_dir, os.W_OK):
        raise PermissionError(f"Cannot write to {cfg_dir}")

    if os.path.exists(cfg_file) and not os.access(cfg_file, os.W_OK):
        raise PermissionError(f"Cannot write to {cfg_file}")

    with open(cfg_file, 'w') as f:
        json.dump(cfg, f, indent=2)


def load_servers():
    response = requests.get(MULLVAD_SERVERS_URL)

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if IS_DEBUG:
            raise e

        return None

    return response.json()


def filter_servers(server_list: dict, filter_codes: list[str]):
    # We expect filter codes to be in either of 2 formats:
    # 'xx' country code; or
    # 'xx-yyy' full location code (city)

    available_countries = set([location_code[:2]
                              for location_code in server_list['locations']])
    available_locations = set(server_list['locations'])

    for code in filter_codes:
        if len(code) not in [2, 6]:
            raise ValueError(f"Invalid filter code: {code}")

        if len(code) == 6 and code[2] != '-':
            raise ValueError(f"Invalid filter code: {code}")

        if len(code) == 6 and code not in available_locations:
            raise ValueError(f"Unknown location code: {code}")

        if len(code) == 2 and code not in available_countries:
            raise ValueError(f"Unknown country code: {code}")

    eligible_servers = []

    for server in server_list['wireguard']['relays']:
        location_code = server['location']
        country_code = location_code[:2]

        if location_code in filter_codes or country_code in filter_codes:

            if server['active'] == False:
                continue

            eligible_servers.append(server)

    return eligible_servers


def get_mullvad_address(pubkey: str, account: str):
    response = requests.post(
        "https://api.mullvad.net/wg",
        data={
            "account": account,
            "pubkey": pubkey
        }
    )

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if IS_DEBUG:
            raise e

        return None

    return response.text


def cmd_update(wg_dir: str, filter_codes: list[str], iface: str):
    cfg = load_cfg(wg_dir, iface)

    server_list = load_servers()

    if server_list is None:
        raise ValueError("Failed to fetch server list")

    eligible_servers = filter_servers(server_list, filter_codes)

    # If less than 3 servers are available, raise a warning
    if len(eligible_servers) < 3:
        print(
            f"Warning: Less than 3 servers matching your filters. It is recommended to have at least 3 servers available")

    # If only 1 server is available, raise an error
    if len(eligible_servers) == 1:
        raise ValueError(
            "Only 1 server available. You need to have at least 2 servers available to switch between")

    if IS_DEBUG:
        for server in eligible_servers:
            # Print server [hostname, location, ipv4_addr_in, ipv6_addr_in]
            print("Eligible server found:",
                  server['hostname'], server['location'], server['ipv4_addr_in'], server['ipv6_addr_in'])

    cfg['servers'] = eligible_servers

    save_cfg(cfg, wg_dir, iface)


def get_template_iface_config(wg_dir: str, iface: str):
    iface_file = f"{wg_dir}/{iface}.conf.template"
    template = ""
    if not os.path.exists(iface_file):
        template = """
# Server: $SERVER_NAME
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $ADDRESS
DNS = 10.64.0.1

[Peer]
PublicKey = $PUBLIC_KEY
Endpoint = $SERVER_IP:$SERVER_PORT
AllowedIPs = $ALLOWED_IPS
"""
    else:
        with open(iface_file, 'r') as f:
            template = f.read()

    template = f"""
# DO NOT EDIT THIS FILE. IT IS AUTOGENERATED BY MULLVADSHAL
# IT WILL BE OVERWRITTEN ON THE NEXT 'update' COMMAND
# To customize this file, create/edit {iface}.conf.template instead
# Check the documentation for more details

{template}
"""

    return template


def get_random_port():
    ranges = [
        (4000, 33433),
        (33565, 51800),
        (52001, 60000),
    ]
    selected_range = random.choice(ranges)
    return random.randint(selected_range[0], selected_range[1])


def interface_exists(iface: str) -> bool:
    try:
        subprocess.run(
            ["ip", "link", "show", iface],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError:
        return False


def wg_configure(iface: str, iface_file: str, sudo: bool):
    if not os.path.isfile(iface_file):
        raise FileNotFoundError(
            f"Configuration file does not exist: {iface_file}")

    # Construct commands
    cmd_down = f"wg-quick down {iface_file}"
    cmd_up = f"wg-quick up {iface_file}"

    if sudo:
        cmd_down = f"sudo {cmd_down}"
        cmd_up = f"sudo {cmd_up}"

    if interface_exists(iface):
        try:
            run_command(
                cmd_down, f"Failed to bring down WireGuard interface {iface}.")
        except RuntimeError as e:
            raise RuntimeError(
                f"Error while bringing down WireGuard interface {iface}: {e}")

    try:
        run_command(
            cmd_up, f"Failed to configure WireGuard interface {iface}.")
    except RuntimeError as e:
        raise RuntimeError(
            f"Error while setting up WireGuard interface {iface}: {e}")


def cmd_jump(wg_dir: str, iface: str, sudo: bool, server_net_mode: str, route_net_mode: str):
    cfg = load_cfg(wg_dir, iface)

    if len(cfg['servers']) == 0:
        raise ValueError(
            "No servers available. You need to run 'update' first")

    if cfg['address'] is None:
        raise ValueError(
            "Your interface is not registered with Mullvad. Run 'auth' first")

    eligible_servers = [server for server in cfg['servers']
                        if server['hostname'] != cfg['last-server']]

    if len(eligible_servers) == 0:
        raise ValueError("No servers available to switch to")

    new_server = random.choice(eligible_servers)

    if IS_DEBUG:
        print("Switching to", new_server['hostname'])

    iface_file = f"{wg_dir}/{iface}.conf"
    iface_config_template = get_template_iface_config(wg_dir, iface)

    server_ip = new_server['ipv4_addr_in'] if server_net_mode == 'ipv4' else new_server['ipv6_addr_in']

    (peer_addr_ipv4, peer_addr_ipv6) = cfg['address'].split(',')
    peer_addr = peer_addr_ipv4 if server_net_mode == 'ipv4' else peer_addr_ipv6

    allowed_ips = ""
    if route_net_mode == 'ipv4':
        allowed_ips = "0.0.0.0/0"
    elif route_net_mode == 'ipv6':
        allowed_ips = "::/0"
    elif route_net_mode == 'all':
        allowed_ips = "0.0.0.0/0, ::/0"
    else:
        raise ValueError(
            f"Invalid route network mode: {route_net_mode}, must be either 'ipv4', 'ipv6' or 'all")

    replacements = {
        "$SERVER_NAME": new_server['hostname'],
        "$PRIVATE_KEY": cfg['keypair']['privkey'],
        "$ADDRESS": peer_addr,
        "$PUBLIC_KEY": new_server['public_key'],
        "$SERVER_IP": server_ip,
        "$SERVER_PORT": get_random_port(),
        "$ALLOWED_IPS": allowed_ips
    }

    iface_config = iface_config_template
    for key, value in replacements.items():
        iface_config = iface_config.replace(key, str(value))

    with open(iface_file, 'w') as f:
        f.write(iface_config)

    wg_configure(iface, iface_file, sudo)


def cmd_keys():
    keys = wg_keypair()

    print("Private key:", keys['privkey'])
    print("Public key:", keys['pubkey'])


def cmd_auth(wg_dir: str, iface: str):
    cfg = load_cfg(wg_dir, iface)
    if cfg['address'] is not None:
        print(f'The interface "{iface}" is already registered with Mullvad')
        yn = input("Do you want to re-register? (y/n): ")

        if yn.lower() != 'y':
            return

    # Prompt user for account number
    account = input("Enter your Mullvad account number: ")

    if not account.isdigit():
        raise ValueError("Account number must be a number")

    if cfg['keypair'] is None:
        cfg['keypair'] = wg_keypair()

    if cfg['address'] is None:
        cfg['address'] = get_mullvad_address(cfg['keypair']['pubkey'], account)
        if cfg['address'] is None:
            raise ValueError(
                "Failed to get Mullvad address. Check your account number and device limit")

    save_cfg(cfg, wg_dir, iface)


def main():
    global IS_DEBUG
    # Available commands:
    # - update: fetches the latest server list from Mullvad API and regenerates the wireguard configs
    # - jump: switches to a random server in the list that is not current server

    # Arguments tp update command
    # - wg-dir: directory where wireguard configs are stored
    # - iface: wireguard interface name
    # - filter: comma-separated list of country codes or location codes to filter servers by

    parser = argparse.ArgumentParser(
        prog='mullvadshal',
        description='Automated server-hopping for Mullvad VPN for WireGuard and Linux'
    )

    parser.add_argument('--debug', default=False,
                        action='store_true', help='Enable debug mode')

    subparsers = parser.add_subparsers(dest='command', required=True)

    auth_parser = subparsers.add_parser(
        'auth', help='Authenticate with Mullvad API')
    update_parser = subparsers.add_parser(
        'update', help='Fetches the latest server list from Mullvad API and regenerates the wireguard configs')
    jump_parser = subparsers.add_parser(
        'jump', help='Switches to a random server in the list that is not current server')
    keys_parser = subparsers.add_parser(
        'keys', help='Generate a new WireGuard keypair')

    auth_parser.add_argument(
        '--wg-dir', help='Directory where wireguard configs are stored', default='/etc/wireguard')
    auth_parser.add_argument(
        '--iface', help='Wireguard interface name', default='wg-mvdh0')

    update_parser.add_argument(
        '--wg-dir', help='Directory where wireguard configs are stored', default='/etc/wireguard')
    update_parser.add_argument(
        '--iface', help='Wireguard interface name', default='wg-mvdh0')
    update_parser.add_argument(
        '--filter', help='Comma-separated list of country codes or location codes to filter servers by', required=True)

    jump_parser.add_argument(
        '--wg-dir', help='Directory where wireguard configs are stored', default='/etc/wireguard')
    jump_parser.add_argument(
        '--iface', help='Wireguard interface name', default='wg-mvdh0')
    jump_parser.add_argument(
        '--sudo', help='Use sudo to switch interfaces', action='store_true', default=False)
    jump_parser.add_argument(
        '--server-net-mode', help='Server network mode', default='ipv4')
    jump_parser.add_argument(
        '--route-net-mode', help='Which traffic to route, ipv4, ipv6 or all', default='all')

    args = parser.parse_args()

    IS_DEBUG = args.debug

    wg_dir = None
    iface = None
    filters = None

    if args.command in ['update', 'jump', 'auth']:
        wg_dir = os.path.abspath(args.wg_dir)
        iface = args.iface

    if args.command == 'update':
        filters = args.filter.split(',')

    try:
        if shutil.which("wg-quick") is None:
            raise RuntimeError(
                "wg-quick is not installed. Please install WireGuard tools")

        if not is_valid_interface_name(iface):
            raise ValueError(f"Invalid interface name: {iface}")

        if args.command == 'update':
            cmd_update(
                wg_dir,
                filters,
                iface
            )
        elif args.command == 'jump':
            server_net_mode = args.server_net_mode
            if server_net_mode not in ['ipv4', 'ipv6']:
                raise ValueError(
                    f"Invalid server network mode: {server_net_mode}, must be either 'ipv4' or 'ipv6'")

            route_net_mode = args.route_net_mode
            if route_net_mode not in ['ipv4', 'ipv6', 'all']:
                raise ValueError(
                    f"Invalid route network mode: {route_net_mode}, must be either 'ipv4', 'ipv6' or 'all")

            if not args.sudo and os.geteuid() != 0:
                raise PermissionError(
                    "You need to run this command as root or use --sudo flag")

            cmd_jump(
                wg_dir,
                iface,
                args.sudo,
                server_net_mode,
                route_net_mode
            )
        elif args.command == 'keys':
            cmd_keys()
        elif args.command == 'auth':
            cmd_auth(
                wg_dir,
                iface
            )
        else:
            raise ValueError(f"Unknown command: {args.command}")
    except Exception as e:
        print(f"Error: {e}")

        if IS_DEBUG:
            raise e

        exit(1)
