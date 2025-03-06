# Lio-Hole

Lio-Hole is a network-wide DNS-based content filtering system that blocks unwanted content at the DNS level. It's designed to be lightweight, easy to use, and effective at blocking ads, trackers, and other unwanted content.

## Features

- **Network-wide filtering**: Block unwanted content on all devices connected to your network
- **DNS-based**: Uses DNS filtering to block content, no client-side software needed
- **Customizable**: Add your own domains to allowlist or blocklist
- **Regex support**: Use regular expressions for more flexible filtering
- **Statistics**: View query logs and blocking statistics
- **Web Interface**: Simple web dashboard for administration (optional)
- **API**: REST API for integration with other tools and services
- **Cross-platform**: Works on both Linux and macOS

## Installation

### Prerequisites

- Linux-based system (Debian, Ubuntu, Fedora, etc.) or macOS
- SQLite3
- Curl
- Bash
- On macOS: Homebrew (recommended)

### Quick Install

```bash
curl -sSL https://install.liohole.org | bash
```

### Manual Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/liohole/liohole.git
   ```

2. Run the installation script:
   ```bash
   cd liohole
   sudo bash install.sh
   ```

3. Configure your network to use Lio-Hole as the DNS server.

## Usage

Lio-Hole can be controlled using the `liohole` command-line tool. Here are some common commands:

```bash
# Show Lio-Hole status
liohole status

# Update blocklists
liohole update-gravity

# Add domain to allowlist
liohole allow example.com

# Add domain to blocklist
liohole block badsite.com

# Disable filtering temporarily
liohole disable 30m  # Disable for 30 minutes

# Show DNS query log
liohole tail

# Check if a domain is blocked
liohole query doubleclick.net
```

## Configuration

Lio-Hole configuration files are stored in `/etc/liohole/` on Linux or `/usr/local/etc/liohole/` on macOS. The main configuration file is `liohole.conf`.

### Adding Blocklist Sources

You can add new blocklist sources using the `liohole add-source` command:

```bash
liohole add-source https://example.com/blocklist.txt "My custom blocklist"
```

### Web Interface

The web interface is available at `http://your-server-ip:80/admin/` by default. You can set a password for the web interface using:

```bash
liohole set-password
```

## Directory Structure

On Linux:
- `/opt/liohole/`: Main program files
- `/etc/liohole/`: Configuration files
- `/var/lib/liohole/`: Data files, including the database
- `/var/log/liohole/`: Log files
- `/var/www/liohole/`: Web interface files

On macOS:
- `/usr/local/opt/liohole/`: Main program files
- `/usr/local/etc/liohole/`: Configuration files
- `/usr/local/var/lib/liohole/`: Data files, including the database
- `/usr/local/var/log/liohole/`: Log files
- `/usr/local/var/www/liohole/`: Web interface files

## How It Works

1. Lio-Hole sets up a DNS server on your network
2. It downloads lists of domains known to serve ads, tracking, and malware
3. When a device on your network makes a DNS query for a domain
4. If the domain is on a blocklist, Lio-Hole returns a null response or a local IP
5. If the domain is not on a blocklist, Lio-Hole forwards the query to an upstream DNS server

## Troubleshooting

If you encounter any issues, check the log files in `/var/log/liohole/` (Linux) or `/usr/local/var/log/liohole/` (macOS).

Common issues:
- DNS service not running: `liohole restart-dns`
- Blocklists not updating: `liohole update-gravity`
- DNS queries not being blocked: `liohole status` to check if filtering is enabled

## macOS-Specific Notes

When running on macOS:
- You may need to manually configure your network settings to use Lio-Hole as your DNS server
- Some commands require root privileges with `sudo`
- The DNS server needs to be started explicitly: `sudo liohole restart-dns`

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

Lio-Hole is inspired by Pi-hole and other DNS-based filtering solutions. Thanks to all the maintainers of public domain blocklists that make projects like this possible.