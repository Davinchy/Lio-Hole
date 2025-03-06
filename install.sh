#!/usr/bin/env bash
# LioHole Installer
# Installs and configures LioHole on your system

# Exit on error
set -e

# Check if script is run as root or with sudo
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run with sudo or as root" 
    exit 1
fi

# Terminal colors
NC='\033[0m' # No Color
GREEN='\033[1;32m'
RED='\033[1;31m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
TICK="[${GREEN}✓${NC}]"
CROSS="[${RED}✗${NC}]"
INFO="[${BLUE}i${NC}]"
WARN="[${YELLOW}!${NC}]"

# Detect OS
OS="$(uname -s)"
IS_MACOS=false
if [[ "$OS" == "Darwin" ]]; then
    IS_MACOS=true
fi

# LioHole directories (macOS friendly paths)
if [[ "$IS_MACOS" == true ]]; then
    LIOHOLE_BASE_DIR="/usr/local/opt/liohole"
    LIOHOLE_CONFIG_DIR="/usr/local/etc/liohole"
    LIOHOLE_DATA_DIR="/usr/local/var/lib/liohole"
    LIOHOLE_LOG_DIR="/usr/local/var/log/liohole"
    LIOHOLE_WEB_DIR="/usr/local/var/www/liohole"
    LIOHOLE_CACHE_DIR="${LIOHOLE_DATA_DIR}/cache"
    LIOHOLE_BIN_DIR="/usr/local/bin"
else
    # Linux paths
    LIOHOLE_BASE_DIR="/opt/liohole"
    LIOHOLE_CONFIG_DIR="/etc/liohole"
    LIOHOLE_DATA_DIR="/var/lib/liohole"
    LIOHOLE_LOG_DIR="/var/log/liohole"
    LIOHOLE_WEB_DIR="/var/www/liohole"
    LIOHOLE_CACHE_DIR="${LIOHOLE_DATA_DIR}/cache"
    LIOHOLE_BIN_DIR="/usr/local/bin"
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check and install dependencies
check_dependencies() {
    echo -e "${INFO} Checking dependencies..."
    
    local deps_to_install=()
    local pkg_manager=""
    
    # Determine package manager
    if [[ "$IS_MACOS" == true ]]; then
        if command_exists brew; then
            pkg_manager="brew"
        else
            echo -e "${CROSS} Homebrew not found. Please install Homebrew first:"
            echo "Visit https://brew.sh and follow the installation instructions."
            exit 1
        fi
    elif command_exists apt-get; then
        pkg_manager="apt-get"
    elif command_exists dnf; then
        pkg_manager="dnf"
    elif command_exists yum; then
        pkg_manager="yum"
    elif command_exists pacman; then
        pkg_manager="pacman"
    else
        echo -e "${CROSS} Unsupported package manager. Please install dependencies manually."
        echo "Required packages: curl sqlite3 grep jq"
        exit 1
    fi
    
    # Check for required commands
    if [[ "$IS_MACOS" == true ]]; then
        for cmd in curl sqlite3 grep jq; do
            if ! command_exists "$cmd"; then
                case "$cmd" in
                    sqlite3)
                        # On macOS, sqlite might be installed but not linked
                        if [ -e /usr/bin/sqlite3 ]; then
                            continue
                        fi
                        deps_to_install+=("sqlite")
                        ;;
                    *)
                        deps_to_install+=("$cmd")
                        ;;
                esac
            fi
        done
    else
        # Linux
        for cmd in curl sqlite3 grep dig ip mktemp ps jq; do
            if ! command_exists "$cmd"; then
                case "$cmd" in
                    dig)
                        deps_to_install+=("dnsutils")
                        ;;
                    *)
                        deps_to_install+=("$cmd")
                        ;;
                esac
            fi
        done
    fi
    
    # Install missing dependencies
    if [ ${#deps_to_install[@]} -gt 0 ]; then
        echo -e "${INFO} Installing dependencies: ${deps_to_install[*]}"
        case "$pkg_manager" in
            brew)
                brew install "${deps_to_install[@]}"
                ;;
            apt-get)
                apt-get update
                apt-get install -y "${deps_to_install[@]}"
                ;;
            dnf|yum)
                "$pkg_manager" install -y "${deps_to_install[@]}"
                ;;
            pacman)
                pacman -Sy --noconfirm "${deps_to_install[@]}"
                ;;
        esac
    else
        echo -e "${TICK} All dependencies are already installed."
    fi
}

# Function to create necessary directories
create_directories() {
    echo -e "${INFO} Creating LioHole directories..."
    
    mkdir -p "$LIOHOLE_BASE_DIR"
    mkdir -p "$LIOHOLE_CONFIG_DIR"
    mkdir -p "$LIOHOLE_DATA_DIR"
    mkdir -p "$LIOHOLE_LOG_DIR"
    mkdir -p "$LIOHOLE_WEB_DIR"
    mkdir -p "$LIOHOLE_CACHE_DIR"
    mkdir -p "${LIOHOLE_BASE_DIR}/bin"
    mkdir -p "${LIOHOLE_BASE_DIR}/schema"
    
    echo -e "${TICK} Directories created."
}

# Function to copy LioHole files to the correct locations
copy_files() {
    echo -e "${INFO} Copying LioHole files..."
    
    # Get the directory where this script is located
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Copy main script
    cp "${script_dir}/liohole.sh" "${LIOHOLE_BIN_DIR}/liohole"
    chmod +x "${LIOHOLE_BIN_DIR}/liohole"
    
    # Copy schema files
    cp "${script_dir}/schema/database.sql" "${LIOHOLE_BASE_DIR}/schema/"
    
    # Create a symbolic link to the liohole command if needed
    if [[ "$LIOHOLE_BIN_DIR" != "/usr/bin" ]] && [[ ! -e "/usr/bin/liohole" ]]; then
        ln -sf "${LIOHOLE_BIN_DIR}/liohole" "/usr/bin/liohole"
    fi
    
    echo -e "${TICK} Files copied."
}

# Function to detect network interface and IP
detect_network() {
    echo -e "${INFO} Detecting network configuration..."
    
    # Get default interface and IP based on OS
    local default_iface=""
    local ip_address=""
    
    if [[ "$IS_MACOS" == true ]]; then
        # Get active network service
        local network_service
        network_service=$(networksetup -listallnetworkservices | grep -v '*' | grep -v "Wi-Fi" | head -2 | tail -1)
        
        if [[ -z "$network_service" ]]; then
            network_service=$(networksetup -listallnetworkservices | grep -v '*' | head -2 | tail -1)
        fi
        
        if [[ -n "$network_service" ]]; then
            # Get interface for the service
            default_iface=$(networksetup -listallhardwareports | grep -A 1 "$network_service" | grep "Device:" | awk '{print $2}')
            # Get IP for the interface
            ip_address=$(ipconfig getifaddr "$default_iface" 2>/dev/null)
        fi
    else
        # Linux approach
        default_iface=$(ip route | grep default | awk '{print $5}' | head -n 1)
        if [[ -n "$default_iface" ]]; then
            ip_address=$(ip -o -4 addr show dev "$default_iface" | awk '{print $4}' | cut -d'/' -f1 | head -n 1)
        fi
    fi
    
    if [[ -z "$default_iface" ]]; then
        echo -e "${WARN} Could not detect default network interface."
        echo -e "${INFO} Please specify your network interface (e.g. en0, eth0, wlan0):"
        read -r default_iface
    fi
    
    if [[ -z "$ip_address" ]]; then
        echo -e "${WARN} Could not detect IP address for interface $default_iface."
        echo -e "${INFO} Please specify your IP address:"
        read -r ip_address
    fi
    
    echo -e "${TICK} Network detected: Interface $default_iface, IP $ip_address"
    
    # Save network configuration
    cat > "${LIOHOLE_CONFIG_DIR}/network.conf" << EOF
# LioHole Network Configuration
interface=$default_iface
ip_address=$ip_address
EOF
}

# Function to initialize the database
init_database() {
    echo -e "${INFO} Initializing database..."
    
    local db_file="${LIOHOLE_DATA_DIR}/liohole.db"
    local schema="${LIOHOLE_BASE_DIR}/schema/database.sql"
    
    if [[ -f "$schema" ]]; then
        sqlite3 "$db_file" < "$schema"
        echo -e "${TICK} Database initialized."
    else
        echo -e "${CROSS} Schema file not found. Database initialization failed."
        exit 1
    fi
}

# Function to create basic configuration
create_config() {
    echo -e "${INFO} Creating configuration files..."
    
    # Create main config file
    cat > "${LIOHOLE_CONFIG_DIR}/liohole.conf" << EOF
# LioHole Main Configuration
dns_port=53
web_port=80
query_logging=true
blocking_mode=NULL
privacy_level=0
web_password=
EOF

    # Create DNS config file with OS-specific settings
    if [[ "$IS_MACOS" == true ]]; then
        # macOS DNS configuration
        cat > "${LIOHOLE_CONFIG_DIR}/liohole-dns.conf" << EOF
# LioHole DNS Server Configuration for macOS
port=53
filtering_enabled=true
pidfile=/usr/local/var/run/liohole-dns.pid
logfile=${LIOHOLE_LOG_DIR}/dns.log
upstream_dns=1.1.1.1,8.8.8.8
block_response=0.0.0.0
EOF
    else
        # Linux DNS configuration
        cat > "${LIOHOLE_CONFIG_DIR}/liohole-dns.conf" << EOF
# LioHole DNS Server Configuration
port=53
filtering_enabled=true
pidfile=/var/run/liohole-dns.pid
logfile=${LIOHOLE_LOG_DIR}/dns.log
upstream_dns=1.1.1.1,8.8.8.8
block_response=0.0.0.0
EOF
    fi

    echo -e "${TICK} Configuration files created."
}

# Main installation function
install_liohole() {
    echo -e "${INFO} Starting LioHole installation on ${OS}..."
    
    # Check and install dependencies
    check_dependencies
    
    # Create necessary directories
    create_directories
    
    # Copy files
    copy_files
    
    # Detect network configuration
    detect_network
    
    # Create configuration
    create_config
    
    # Initialize database
    init_database
    
    echo -e "\n${TICK} LioHole installation completed successfully!"
    echo -e "${INFO} You can now use 'liohole' command to manage your LioHole installation."
    echo -e "${INFO} Run 'liohole help' to see available commands."
    echo -e "${INFO} Run 'liohole update-gravity' to download blocklists."
    
    # macOS specific notes
    if [[ "$IS_MACOS" == true ]]; then
        echo -e "\n${INFO} macOS specific notes:"
        echo -e "  - You may need to manually configure your network settings to use LioHole as your DNS server"
        echo -e "  - To start DNS service: sudo liohole restart-dns"
        echo -e "  - You may need to use sudo for all liohole commands that require administrative privileges"
    fi
}

# Run the installer
install_liohole