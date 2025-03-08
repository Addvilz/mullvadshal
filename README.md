# Mullvadshål

Mullvadshål (`mullvadshal`) is an automated server-hopping tool for **Mullvad VPN** using **WireGuard** on Linux. It allows you to automatically switch to different Mullvad servers, enhancing security and privacy.

## Why?

When using a VPN, staying connected to the same server for prolonged periods introduces certain risks. **Mullvadshål** mitigates these by allowing you to automate periodic server changes, reducing exposure to various attack vectors:

- **Minimizing Traffic Correlation Attacks**: Attackers attempting to track users often analyze incoming and outgoing traffic to correlate activity. Frequent server switching disrupts patterns, making it harder to establish a link between a user and their online actions.
- **Disrupting Long-Term Tracking**: Some ISPs, adversaries, or malicious actors attempt to profile VPN users based on consistent IP usage. Changing VPN servers frequently obfuscates user activity and makes long-term tracking more difficult.
- **Reducing Exposure to Compromised Servers**: VPN servers can be compromised by attackers or monitored by authorities. Regularly switching reduces the risk of prolonged exposure to any single compromised endpoint.
- **Enhancing Anonymity in Shared Exit Nodes**: Mullvad VPN servers act as shared exit nodes, meaning multiple users are assigned the same IP. By switching servers, a user benefits from additional layers of obfuscation and blends in with different traffic groups over time.
- **Bypassing Geo-Restrictions & Network Censorship**: Some websites and services impose restrictions based on VPN server IPs. Rotating through servers increases the chances of maintaining access without detection.

For privacy-conscious users, journalists, activists, and those in restrictive environments, automating server hops can be a crucial tool for reducing digital footprints and maintaining operational security.

## OS support

Only modern Linux distributions are supported. There are no plans to support other operating systems.

Mullvadshål might work on Mac, if you try hard enough.

## Recommended Use
To maximize effectiveness, **Mullvadshål** should be automated using `cron` or/and triggered by user actions. It is recommended to:

- **Update the server list at least once per day** to ensure the latest Mullvad VPN servers are available (mullvadshal update).
- **Perform server jumps during periods of inactivity** to minimize disruption. A good approach is to run it at times when the user is away, such on cron schedule when the screen is locked, when the screen is unlocked, or/and whenever the system resumes from suspension (e.g. After=suspend.target as a Systemd service). (mullvadshal jump)

## Features
- **Automated Server Updates:** Fetches the latest Mullvad WireGuard server list.
- **Periodic Server Hopping:** Switches to a random Mullvad server to reduce tracking.
- **Configurable Network Modes:** Supports IPv4, IPv6, and dual-stack configurations.
- **Persistent Configuration:** Stores WireGuard settings securely.
- **Lightweight & CLI-Based:** Ideal for cron jobs and automation.

## TODO
- Support for multi-hop
- Kill-switch while jumping

## Installation
Ensure you have Python and WireGuard installed:

```sh
pip install mullvadshal
```

Or install manually by cloning the repository:

```sh
git clone https://github.com/Addvilz/mullvadshal.git
cd mullvadshal
pip install .
```

## Usage
### Authenticate with Mullvad
Before using the tool, authenticate your WireGuard interface with your Mullvad account:

```sh
mullvadshal auth
```
This will prompt for your **Mullvad account number**.

### Update Mullvad Server List
To fetch the latest Mullvad WireGuard servers, run:

```sh
mullvadshal update --filter se,de,fi
```
This command filters servers by **Sweden (se), Germany (de), and Finland (fi)**.
You can also specify a location, like `se-got`.

### Perform a Server Hop
To switch to a new random server (within the previously filtered server list):

```sh
mullvadshal jump [--sudo]
```
**Warning:** Jumping servers disrupts your network connection momentarily.

Jump command should generally be either run as root, or with no password sudoers configured.

If you do not use cron, you can also simply run it with `--sudo` and type in your sudo password.

## Automating with Cron
To automate server updates and jumps:

1. Open your crontab:
   ```sh
   crontab -e
   ```
2. Add the following lines:
   ```sh
   # Update server list daily at 3 AM
   0 3 * * * mullvadshal update --filter se,de,fi

   # Jump to a new server every hour
   0 * * * * mullvadshal jump
   ```

## Troubleshooting

**Ensure `wg-quick` is installed on your system:**

For **Debian/Ubuntu-based distributions (APT package manager):**
```bash
sudo apt update && sudo apt install -y wireguard-tools
```

For **RHEL/CentOS/Fedora-based distributions (RPM package manager):**
```bash
sudo dnf install -y wireguard-tools   # For Fedora, RHEL 8+, and CentOS 8+
sudo yum install -y wireguard-tools   # For older RHEL/CentOS versions
```

For **Arch Linux and Manjaro (Pacman package manager):**
```bash
sudo pacman -S wireguard-tools
```

For **OpenSUSE (Zypper package manager):**
```bash
sudo zypper install -y wireguard-tools
```

- Run with `--debug` to get detailed error messages.
- If an error occurs during `jump`, verify that the WireGuard interface is correctly configured.

## License
Mullvadshål is licensed under the Apache License Version 2.0

## Contributing
Pull requests and bug reports are welcome. Please submit issues on [GitHub](https://github.com/Addvilz/mullvadshal).


## Disclaimer

**Mullvadshål** is an independent project and is **not affiliated with, endorsed by, or associated with Mullvad VPN AB**. All trademarks, service marks, and company names belong to their respective owners.

This software is provided "as is," without any warranties or guarantees. The authors are not responsible for any misuse, legal issues, or damages resulting from the use of this project. Use at your own risk and ensure compliance with applicable laws and regulations.
