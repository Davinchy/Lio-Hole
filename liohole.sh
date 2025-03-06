#!/usr/bin/env bash
# LioHole: Network-wide DNS-based content filtering
# A clean implementation inspired by Pi-hole functionality
# Licensed under the MIT License

# ------- Core Constants -------
LIOHOLE_VERSION="1.0.0-mac"

# Detect OS
OS="$(uname -s)"
IS_MACOS=false
if [[ "$OS" == "Darwin" ]]; then
    IS_MACOS=true
fi

# Set up directories based on OS
if [[ "$IS_MACOS" == true ]]; then
    # macOS paths
    LIOHOLE_BASE_DIR="/usr/local/opt/liohole"
    LIOHOLE_CONFIG_DIR="/usr/local/etc/liohole"
    LIOHOLE_DATA_DIR="/usr/local/var/lib/liohole"
    LIOHOLE_LOG_DIR="/usr/local/var/log/liohole"
    LIOHOLE_WEB_DIR="/usr/local/var/www/liohole"
    LIOHOLE_CACHE_DIR="${LIOHOLE_DATA_DIR}/cache"
    LIOHOLE_BIN_DIR="/usr/local/bin"
    LIOHOLE_COMMAND="${LIOHOLE_BIN_DIR}/liohole"
else
    # Linux paths
    LIOHOLE_BASE_DIR="/opt/liohole"
    LIOHOLE_CONFIG_DIR="/etc/liohole"
    LIOHOLE_DATA_DIR="/var/lib/liohole"
    LIOHOLE_LOG_DIR="/var/log/liohole"
    LIOHOLE_WEB_DIR="/var/www/liohole"
    LIOHOLE_CACHE_DIR="${LIOHOLE_DATA_DIR}/cache"
    LIOHOLE_BIN_DIR="/usr/local/bin"
    LIOHOLE_COMMAND="${LIOHOLE_BIN_DIR}/liohole"
fi

# ------- UI Constants -------
# Terminal colors for user interaction
NC='\033[0m' # No Color
GREEN='\033[1;32m'
RED='\033[1;31m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
TICK="[${GREEN}✓${NC}]"
CROSS="[${RED}✗${NC}]"
INFO="[${BLUE}i${NC}]"
WARN="[${YELLOW}!${NC}]"
OVER="\r\033[K"

# ------- Database Files -------
DB_FILE="${LIOHOLE_DATA_DIR}/liohole.db"
DB_SCHEMA="${LIOHOLE_BASE_DIR}/schema/database.sql"
DB_BACKUP_DIR="${LIOHOLE_DATA_DIR}/backups"

# ------- Config Files -------
CONFIG_FILE="${LIOHOLE_CONFIG_DIR}/liohole.conf"
FTL_CONFIG_FILE="${LIOHOLE_CONFIG_DIR}/liohole-dns.conf"

# ------- Utility Functions -------

# Standardized logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Log to file if log directory exists
    if [ -d "$LIOHOLE_LOG_DIR" ]; then
        echo "[${timestamp}] [${level}] ${message}" >> "${LIOHOLE_LOG_DIR}/liohole.log"
    fi
    
    # Also output to console based on level
    case "$level" in
        "INFO")
            echo -e "  ${INFO} ${message}"
            ;;
        "SUCCESS")
            echo -e "  ${TICK} ${message}"
            ;;
        "ERROR")
            echo -e "  ${CROSS} ${message}"
            ;;
        "WARNING")
            echo -e "  ${WARN} ${message}"
            ;;
    esac
}

# Function to check if the script is run with appropriate privileges
check_privileges() {
    if [[ "$IS_MACOS" == true ]]; then
        # Check for specific operations on macOS that require sudo
        local require_sudo=false
        case "$1" in
            "restart-dns"|"add-source"|"rm-source"|"update-gravity"|"enable"|"disable"|"set-password"|"allow"|"block"|"rm-allow"|"rm-block"|"regex-allow"|"regex-block")
                require_sudo=true
                ;;
        esac
        
        if [[ "$require_sudo" == true && $EUID -ne 0 ]]; then
            log "ERROR" "This command requires root privileges. Try: sudo liohole $*"
            exit 1
        fi
    else
        # Linux check
        if [[ $EUID -ne 0 && "$USER" != "liohole" ]]; then
            log "ERROR" "This command requires root privileges. Try: sudo liohole $*"
            exit 1
        fi
    fi
}

# Function to execute SQLite3 commands safely
db_execute() {
    local query="$1"
    local output
    
    if [ ! -f "$DB_FILE" ]; then
        log "ERROR" "Database file not found at $DB_FILE"
        return 1
    fi
    
    output=$(sqlite3 -cmd ".timeout 30000" "$DB_FILE" "$query" 2>&1)
    local status=$?
    
    if [ $status -ne 0 ]; then
        log "ERROR" "Database query failed: $output"
        return 1
    fi
    
    echo "$output"
    return 0
}

# Function to read configuration value
get_config_value() {
    local key="$1"
    local default="$2"
    local value
    
    if [ -f "$CONFIG_FILE" ]; then
        value=$(grep -E "^${key}=" "$CONFIG_FILE" | cut -d'=' -f2-)
        if [ -n "$value" ]; then
            echo "$value"
            return 0
        fi
    fi
    
    # Return default value if key not found or file doesn't exist
    echo "$default"
    return 0
}

# Function to set configuration value
set_config_value() {
    local key="$1"
    local value="$2"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        mkdir -p "$(dirname "$CONFIG_FILE")"
        touch "$CONFIG_FILE"
    fi
    
    # OS-specific sed in-place edit
    if [[ "$IS_MACOS" == true ]]; then
        if grep -q "^${key}=" "$CONFIG_FILE"; then
            # Key exists, update it
            sed -i '' "s/^${key}=.*/${key}=${value}/" "$CONFIG_FILE"
        else
            # Key doesn't exist, add it
            echo "${key}=${value}" >> "$CONFIG_FILE"
        fi
    else
        # Linux version
        if grep -q "^${key}=" "$CONFIG_FILE"; then
            # Key exists, update it
            sed -i "s/^${key}=.*/${key}=${value}/" "$CONFIG_FILE"
        else
            # Key doesn't exist, add it
            echo "${key}=${value}" >> "$CONFIG_FILE"
        fi
    fi
    
    log "SUCCESS" "Configuration setting '${key}' updated"
    return 0
}

# Function to get DNS value
get_dns_value() {
    local key="$1"
    local default="$2"
    local value
    
    if [ -f "$FTL_CONFIG_FILE" ]; then
        value=$(grep -E "^${key}=" "$FTL_CONFIG_FILE" | cut -d'=' -f2-)
        if [ -n "$value" ]; then
            echo "$value"
            return 0
        fi
    fi
    
    # Return default value if key not found or file doesn't exist
    echo "$default"
    return 0
}

# Function to set DNS configuration value
set_dns_value() {
    local key="$1"
    local value="$2"
    
    if [ ! -f "$FTL_CONFIG_FILE" ]; then
        mkdir -p "$(dirname "$FTL_CONFIG_FILE")"
        touch "$FTL_CONFIG_FILE"
    fi
    
    # OS-specific sed in-place edit
    if [[ "$IS_MACOS" == true ]]; then
        if grep -q "^${key}=" "$FTL_CONFIG_FILE"; then
            # Key exists, update it
            sed -i '' "s/^${key}=.*/${key}=${value}/" "$FTL_CONFIG_FILE"
        else
            # Key doesn't exist, add it
            echo "${key}=${value}" >> "$FTL_CONFIG_FILE"
        fi
    else
        # Linux version
        if grep -q "^${key}=" "$FTL_CONFIG_FILE"; then
            # Key exists, update it
            sed -i "s/^${key}=.*/${key}=${value}/" "$FTL_CONFIG_FILE"
        else
            # Key doesn't exist, add it
            echo "${key}=${value}" >> "$FTL_CONFIG_FILE"
        fi
    fi
    
    log "SUCCESS" "DNS setting '${key}' updated"
    return 0
}

# Function to check if DNS service is running
is_dns_running() {
    local pid_file
    pid_file=$(get_dns_value "pidfile" "/var/run/liohole-dns.pid")
    
    if [[ "$IS_MACOS" == true ]]; then
        # On macOS, use launchctl to check if service is running
        if [ -f "$pid_file" ]; then
            local pid
            pid=$(cat "$pid_file")
            if ps -p "$pid" > /dev/null; then
                return 0 # Running
            fi
        fi
    else
        # Linux check
        if [ -f "$pid_file" ]; then
            local pid
            pid=$(cat "$pid_file")
            if ps -p "$pid" > /dev/null; then
                return 0 # Running
            fi
        fi
    fi
    
    return 1 # Not running
}

# Function to create database backup
backup_database() {
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="${DB_BACKUP_DIR}/liohole_${timestamp}.db"
    
    mkdir -p "$DB_BACKUP_DIR"
    
    if [ -f "$DB_FILE" ]; then
        cp "$DB_FILE" "$backup_file"
        log "SUCCESS" "Database backup created at $backup_file"
        
        # Remove old backups (keep last 10)
        if [[ "$IS_MACOS" == true ]]; then
            # macOS version using find without -printf
            find "$DB_BACKUP_DIR" -name "liohole_*.db" -type f | \
                xargs ls -t | tail -n +11 | xargs rm 2>/dev/null || true
        else
            # Linux version
            find "$DB_BACKUP_DIR" -name "liohole_*.db" -type f -printf '%T@ %p\n' | \
                sort -n | head -n -10 | cut -d' ' -f2- | xargs -r rm
        fi
        
        return 0
    else
        log "ERROR" "Cannot backup database - file does not exist"
        return 1
    fi
}

# Function to check database integrity
check_database() {
    if [ ! -f "$DB_FILE" ]; then
        log "ERROR" "Database file not found"
        return 1
    fi
    
    local result
    result=$(db_execute "PRAGMA integrity_check;")
    
    if [ "$result" == "ok" ]; then
        log "SUCCESS" "Database integrity check passed"
        return 0
    else
        log "ERROR" "Database integrity check failed: $result"
        return 1
    fi
}

# Function to initialize new database
initialize_database() {
    if [ -f "$DB_FILE" ]; then
        backup_database
    fi
    
    mkdir -p "$(dirname "$DB_FILE")"
    
    if [ -f "$DB_SCHEMA" ]; then
        sqlite3 "$DB_FILE" < "$DB_SCHEMA"
        local status=$?
        
        if [ $status -eq 0 ]; then
            log "SUCCESS" "Database initialized successfully"
            return 0
        else
            log "ERROR" "Failed to initialize database"
            return 1
        fi
    else
        log "ERROR" "Database schema file not found at $DB_SCHEMA"
        return 1
    fi
}

# ------- Core Functions -------

# Function to build blocklist database
build_gravity() {
    log "INFO" "Building blocklist database..."
    
    # Create cache directory if it doesn't exist
    mkdir -p "$LIOHOLE_CACHE_DIR"
    
    # Get blocklist sources from database
    local sources
    sources=$(db_execute "SELECT id, url FROM blocklists WHERE enabled = 1;")
    
    if [ -z "$sources" ]; then
        log "WARNING" "No enabled blocklists found"
        return 0
    fi
    
    # Clear the domains table
    db_execute "DELETE FROM domains;"
    
    # Counter for domains
    local total_domains=0
    
    # Process each blocklist source
    echo "$sources" | while IFS='|' read -r id url; do
        log "INFO" "Processing blocklist: $url"
        
        local cache_file="${LIOHOLE_CACHE_DIR}/list_${id}.txt"
        local domain_count=0
        local status=0
        
        # Download the list
        if [[ "$url" == http* ]]; then
            curl --silent --fail --show-error --connect-timeout 10 --output "$cache_file" "$url"
            status=$?
            
            if [ $status -ne 0 ]; then
                log "ERROR" "Failed to download blocklist from $url"
                db_execute "UPDATE blocklists SET status = 'error', last_updated = datetime('now'), comment = 'Download failed' WHERE id = $id;"
                continue
            fi
        elif [[ "$url" == file://* ]]; then
            local file_path
            file_path=$(echo "$url" | cut -d'/' -f3-)
            
            if [ -r "$file_path" ]; then
                cp "$file_path" "$cache_file"
            else
                log "ERROR" "Cannot read local file: $file_path"
                db_execute "UPDATE blocklists SET status = 'error', last_updated = datetime('now'), comment = 'Cannot read file' WHERE id = $id;"
                continue
            fi
        else
            log "ERROR" "Unsupported URL format: $url"
            db_execute "UPDATE blocklists SET status = 'error', last_updated = datetime('now'), comment = 'Unsupported URL format' WHERE id = $id;"
            continue
        fi
        
        # Process the downloaded list (remove comments, whitespace, etc.)
        if [ -f "$cache_file" ]; then
            # Create a temporary file for processing
            local tmp_file
            tmp_file=$(mktemp)
            
            # Process the file - convert to lowercase, remove comments, extract domains
            tr '[:upper:]' '[:lower:]' < "$cache_file" | \
            sed -e 's/\r$//' \
                -e 's/\s*!.*//g' \
                -e 's/\s*\[.*//g' \
                -e '/[a-z]##/d' \
                -e 's/\s*#.*//g' \
                -e 's/^.*\s+//g' \
                -e '/^$/d' > "$tmp_file"
            
            # Count unique domains
            domain_count=$(wc -l < "$tmp_file")
            total_domains=$((total_domains + domain_count))
            
            # Import domains to database
            local import_cmd="BEGIN TRANSACTION; "
            
            # Read line by line and build SQL command
            while IFS= read -r domain; do
                import_cmd+="INSERT OR IGNORE INTO domains (domain, blocklist_id) VALUES ('$domain', $id); "
            done < "$tmp_file"
            
            import_cmd+="COMMIT;"
            
            # Execute the import
            db_execute "$import_cmd"
            
            # Update blocklist status
            db_execute "UPDATE blocklists SET status = 'success', last_updated = datetime('now'), domain_count = $domain_count WHERE id = $id;"
            
            log "SUCCESS" "Imported $domain_count domains from blocklist #$id"
            
            # Clean up
            rm "$tmp_file"
        fi
    done
    
    # Update stats
    db_execute "INSERT OR REPLACE INTO stats (key, value) VALUES ('total_domains', $total_domains);"
    db_execute "INSERT OR REPLACE INTO stats (key, value) VALUES ('last_gravity_update', datetime('now'));"
    
    log "SUCCESS" "Blocklist database updated with $total_domains total domains"
    
    # Reload DNS server if it's running
    if is_dns_running; then
        reload_dns
    fi
    
    return 0
}

# Function to add domain to allowlist
add_to_allowlist() {
    local domain="$1"
    local comment="${2:-Added from command line}"
    
    # Validate domain
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log "ERROR" "Invalid domain: $domain"
        return 1
    fi
    
    # Add domain to allowlist
    local result
    result=$(db_execute "INSERT OR REPLACE INTO allowlist (domain, enabled, comment) VALUES ('$domain', 1, '$comment');")
    local status=$?
    
    if [ $status -eq 0 ]; then
        log "SUCCESS" "Added $domain to allowlist"
        
        # Reload DNS server if it's running
        if is_dns_running; then
            reload_dns
        fi
        
        return 0
    else
        log "ERROR" "Failed to add domain to allowlist: $result"
        return 1
    fi
}

# Function to add domain to blocklist
add_to_blocklist() {
    local domain="$1"
    local comment="${2:-Added from command line}"
    
    # Validate domain
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log "ERROR" "Invalid domain: $domain"
        return 1
    fi
    
    # Add domain to blocklist
    local result
    result=$(db_execute "INSERT OR REPLACE INTO blocklist (domain, enabled, comment) VALUES ('$domain', 1, '$comment');")
    local status=$?
    
    if [ $status -eq 0 ]; then
        log "SUCCESS" "Added $domain to blocklist"
        
        # Reload DNS server if it's running
        if is_dns_running; then
            reload_dns
        fi
        
        return 0
    else
        log "ERROR" "Failed to add domain to blocklist: $result"
        return 1
    fi
}

# Function to add regex to allowlist
add_regex_to_allowlist() {
    local regex="$1"
    local comment="${2:-Added from command line}"
    
    # Add regex to allowlist
    local result
    result=$(db_execute "INSERT OR REPLACE INTO regex_allowlist (regex, enabled, comment) VALUES ('$regex', 1, '$comment');")
    local status=$?
    
    if [ $status -eq 0 ]; then
        log "SUCCESS" "Added regex '$regex' to allowlist"
        
        # Reload DNS server if it's running
        if is_dns_running; then
            reload_dns
        fi
        
        return 0
    else
        log "ERROR" "Failed to add regex to allowlist: $result"
        return 1
    fi
}

# Function to add regex to blocklist
add_regex_to_blocklist() {
    local regex="$1"
    local comment="${2:-Added from command line}"
    
    # Add regex to blocklist
    local result
    result=$(db_execute "INSERT OR REPLACE INTO regex_blocklist (regex, enabled, comment) VALUES ('$regex', 1, '$comment');")
    local status=$?
    
    if [ $status -eq 0 ]; then
        log "SUCCESS" "Added regex '$regex' to blocklist"
        
        # Reload DNS server if it's running
        if is_dns_running; then
            reload_dns
        fi
        
        return 0
    else
        log "ERROR" "Failed to add regex to blocklist: $result"
        return 1
    fi
}

# Function to remove domain from allowlist
remove_from_allowlist() {
    local domain="$1"
    
    # Remove domain from allowlist
    local result
    result=$(db_execute "DELETE FROM allowlist WHERE domain = '$domain';")
    local status=$?
    
    if [ $status -eq 0 ]; then
        log "SUCCESS" "Removed $domain from allowlist"
        
        # Reload DNS server if it's running
        if is_dns_running; then
            reload_dns
        fi
        
        return 0
    else
        log "ERROR" "Failed to remove domain from allowlist: $result"
        return 1
    fi
}

# Function to remove domain from blocklist
remove_from_blocklist() {
    local domain="$1"
    
    # Remove domain from blocklist
    local result
    result=$(db_execute "DELETE FROM blocklist WHERE domain = '$domain';")
    local status=$?
    
    if [ $status -eq 0 ]; then
        log "SUCCESS" "Removed $domain from blocklist"
        
        # Reload DNS server if it's running
        if is_dns_running; then
            reload_dns
        fi
        
        return 0
    else
        log "ERROR" "Failed to remove domain from blocklist: $result"
        return 1
    fi
}

# Function to list domains in allowlist
list_allowlist() {
    log "INFO" "Domains in allowlist:"
    
    local result
    result=$(db_execute "SELECT domain, comment, datetime(date_added, 'localtime') FROM allowlist WHERE enabled = 1 ORDER BY domain;")
    
    if [ -n "$result" ]; then
        echo "Domain                  Added On             Comment"
        echo "----------------------- -------------------- -----------------------"
        echo "$result" | while IFS='|' read -r domain date_added comment; do
            printf "%-23s %-20s %s\n" "$domain" "$date_added" "$comment"
        done
    else
        log "INFO" "No domains in allowlist"
    fi
    
    return 0
}

# Function to list domains in blocklist
list_blocklist() {
    log "INFO" "Domains in blocklist:"
    
    local result
    result=$(db_execute "SELECT domain, comment, datetime(date_added, 'localtime') FROM blocklist WHERE enabled = 1 ORDER BY domain;")
    
    if [ -n "$result" ]; then
        echo "Domain                  Added On             Comment"
        echo "----------------------- -------------------- -----------------------"
        echo "$result" | while IFS='|' read -r domain date_added comment; do
            printf "%-23s %-20s %s\n" "$domain" "$date_added" "$comment"
        done
    else
        log "INFO" "No domains in blocklist"
    fi
    
    return 0
}

# Function to add blocklist source
add_blocklist_source() {
    local url="$1"
    local comment="${2:-Added from command line}"
    
    # Validate URL format
    if [[ ! "$url" =~ ^(http|https|file):// ]]; then
        log "ERROR" "Invalid URL format: $url"
        return 1
    fi
    
    # Add blocklist source
    local result
    result=$(db_execute "INSERT INTO blocklists (url, enabled, comment) VALUES ('$url', 1, '$comment');")
    local status=$?
    
    if [ $status -eq 0 ]; then
        log "SUCCESS" "Added blocklist source: $url"
        return 0
    else
        log "ERROR" "Failed to add blocklist source: $result"
        return 1
    fi
}

# Function to remove blocklist source
remove_blocklist_source() {
    local id="$1"
    
    # Remove blocklist source
    local result
    result=$(db_execute "DELETE FROM blocklists WHERE id = $id;")
    local status=$?
    
    if [ $status -eq 0 ]; then
        log "SUCCESS" "Removed blocklist source with ID: $id"
        return 0
    else
        log "ERROR" "Failed to remove blocklist source: $result"
        return 1
    fi
}

# Function to list blocklist sources
list_blocklist_sources() {
    log "INFO" "Blocklist sources:"
    
    local result
    result=$(db_execute "SELECT id, url, status, domain_count, datetime(last_updated, 'localtime'), comment FROM blocklists WHERE enabled = 1 ORDER BY id;")
    
    if [ -n "$result" ]; then
        echo "ID  URL                                   Status    Domains  Updated              Comment"
        echo "--- ------------------------------------- --------- -------- -------------------- -----------------------"
        echo "$result" | while IFS='|' read -r id url status domain_count last_updated comment; do
            printf "%-3s %-37s %-9s %-8s %-20s %s\n" "$id" "$url" "$status" "$domain_count" "$last_updated" "$comment"
        done
    else
        log "INFO" "No blocklist sources found"
    fi
    
    return 0
}

# Function to enable LioHole filtering
enable_filtering() {
    # Set filtering to enabled
    set_dns_value "filtering_enabled" "true"
    
    # Reload DNS server if it's running
    if is_dns_running; then
        reload_dns
        log "SUCCESS" "LioHole filtering enabled"
    else
        log "SUCCESS" "LioHole filtering will be enabled when the DNS server starts"
    fi
    
    return 0
}

# Function to disable LioHole filtering
disable_filtering() {
    local duration="$1"
    
    if [ -n "$duration" ]; then
        # Parse duration format
        local seconds=0
        
        if [[ "$duration" =~ ^([0-9]+)s$ ]]; then
            # Format: 30s
            seconds="${BASH_REMATCH[1]}"
        elif [[ "$duration" =~ ^([0-9]+)m$ ]]; then
            # Format: 30m
            seconds=$((BASH_REMATCH[1] * 60))
        elif [[ "$duration" =~ ^([0-9]+)h$ ]]; then
            # Format: 2h
            seconds=$((BASH_REMATCH[1] * 3600))
        else
            log "ERROR" "Invalid duration format. Use <number>s, <number>m, or <number>h"
            return 1
        fi
        
        # Set filtering to disabled
        set_dns_value "filtering_enabled" "false"
        
        # Reload DNS server if it's running
        if is_dns_running; then
            reload_dns
            log "SUCCESS" "LioHole filtering disabled for ${duration}"
        else
            log "SUCCESS" "LioHole filtering will be disabled when the DNS server starts"
        fi
        
        # Schedule re-enabling after the specified duration
        (
            sleep "$seconds"
            enable_filtering
            log "INFO" "LioHole filtering automatically re-enabled after ${duration}"
        ) &
    else
        # Set filtering to disabled indefinitely
        set_dns_value "filtering_enabled" "false"
        
        # Reload DNS server if it's running
        if is_dns_running; then
            reload_dns
            log "SUCCESS" "LioHole filtering disabled"
        else
            log "SUCCESS" "LioHole filtering will be disabled when the DNS server starts"
        fi
    fi
    
    return 0
}

# Function to reload DNS server
reload_dns() {
    local pid_file
    pid_file=$(get_dns_value "pidfile" "/var/run/liohole-dns.pid")
    
    if [[ "$IS_MACOS" == true ]]; then
        # macOS reload approach
        if [ -f "$pid_file" ]; then
            local pid
            pid=$(cat "$pid_file")
            
            if ps -p "$pid" > /dev/null; then
                # Send HUP signal to reload
                kill -HUP "$pid"
                log "SUCCESS" "DNS server reloaded"
                return 0
            fi
        fi
    else
        # Linux reload approach
        if [ -f "$pid_file" ]; then
            local pid
            pid=$(cat "$pid_file")
            
            if ps -p "$pid" > /dev/null; then
                # Send HUP signal to reload
                kill -HUP "$pid"
                log "SUCCESS" "DNS server reloaded"
                return 0
            fi
        fi
    fi
    
    log "ERROR" "DNS server is not running"
    return 1
}

# Function to restart DNS server
restart_dns() {
    # OS specific restart
    if [[ "$IS_MACOS" == true ]]; then
        # macOS version
        local pid_file
        pid_file=$(get_dns_value "pidfile" "/usr/local/var/run/liohole-dns.pid")
        
        # First try to stop if running
        if [ -f "$pid_file" ]; then
            local pid
            pid=$(cat "$pid_file")
            
            if ps -p "$pid" > /dev/null; then
                # Send TERM signal to stop
                kill -TERM "$pid"
                # Wait for process to stop
                for i in {1..5}; do
                    if ! ps -p "$pid" > /dev/null; then
                        break
                    fi
                    sleep 1
                done
                
                # Force kill if still running
                if ps -p "$pid" > /dev/null; then
                    kill -KILL "$pid"
                fi
            fi
        fi
        
        # Start DNS service
        if [ -x "${LIOHOLE_BASE_DIR}/bin/liohole-dns" ]; then
            "${LIOHOLE_BASE_DIR}/bin/liohole-dns" -c "$FTL_CONFIG_FILE" -d
            
            # Check if it started
            sleep 2
            if is_dns_running; then
                log "SUCCESS" "DNS server restarted"
                return 0
            else
                log "ERROR" "Failed to start DNS server"
                return 1
            fi
        else
            log "ERROR" "DNS server executable not found. Try installing or rebuilding the DNS service."
            return 1
        fi
    else
        # Linux version
        local pid_file
        pid_file=$(get_dns_value "pidfile" "/var/run/liohole-dns.pid")
        
        # First try to stop
        if [ -f "$pid_file" ]; then
            local pid
            pid=$(cat "$pid_file")
            
            if ps -p "$pid" > /dev/null; then
                # Send TERM signal to stop
                kill -TERM "$pid"
                # Wait for process to stop
                for i in {1..5}; do
                    if ! ps -p "$pid" > /dev/null; then
                        break
                    fi
                    sleep 1
                done
                
                # Force kill if still running
                if ps -p "$pid" > /dev/null; then
                    kill -KILL "$pid"
                fi
            fi
        fi
        
        # Start DNS service
        if [ -x "${LIOHOLE_BASE_DIR}/bin/liohole-dns" ]; then
            "${LIOHOLE_BASE_DIR}/bin/liohole-dns" -c "$FTL_CONFIG_FILE" -d
            
            # Check if it started
            sleep 2
            if is_dns_running; then
                log "SUCCESS" "DNS server restarted"
                return 0
            else
                log "ERROR" "Failed to start DNS server"
                return 1
            fi
        else
            log "ERROR" "DNS server executable not found"
            return 1
        fi
    fi
}

# Function to show LioHole status
show_status() {
    log "INFO" "LioHole Status:"
    
    # Check DNS service
    if is_dns_running; then
        local pid_file
        pid_file=$(get_dns_value "pidfile" "/var/run/liohole-dns.pid")
        local pid
        pid=$(cat "$pid_file")
        
        echo -e "  ${TICK} DNS server is running (PID: $pid)"
        
        # Check if filtering is enabled
        local filtering_enabled
        filtering_enabled=$(get_dns_value "filtering_enabled" "true")
        
        if [ "$filtering_enabled" == "true" ]; then
            echo -e "  ${TICK} LioHole filtering is enabled"
        else
            echo -e "  ${CROSS} LioHole filtering is disabled"
        fi
    else
        echo -e "  ${CROSS} DNS server is not running"
    fi
    
    # Get statistics
    local stats
    stats=$(db_execute "SELECT key, value FROM stats;")
    
    if [ -n "$stats" ]; then
        echo -e "\nStatistics:"
        echo "$stats" | while IFS='|' read -r key value; do
            case "$key" in
                "total_domains")
                    echo "  Total domains in blocklist: $value"
                    ;;
                "last_gravity_update")
                    echo "  Last blocklist update: $value"
                    ;;
                "queries_today")
                    echo "  DNS queries today: $value"
                    ;;
                "blocked_today")
                    echo "  Queries blocked today: $value"
                    ;;
            esac
        done
    fi
    
    # Get OS-specific info
    if [[ "$IS_MACOS" == true ]]; then
        echo -e "\nSystem Information:"
        echo "  Operating System: macOS $(sw_vers -productVersion)"
    else
        # Linux info
        if [ -f "/etc/os-release" ]; then
            echo -e "\nSystem Information:"
            echo "  Operating System: $(grep -oP '(?<=^PRETTY_NAME=).+' /etc/os-release | tr -d '"')"
        fi
    fi
    
    # Get version
    echo -e "\nVersion:"
    echo "  LioHole: $LIOHOLE_VERSION"
    
    return 0
}

# Function to tail DNS logs
tail_logs() {
    local filter="$1"
    local log_file
    log_file=$(get_dns_value "logfile" "/var/log/liohole/dns.log")
    
    if [ ! -f "$log_file" ]; then
        log "ERROR" "DNS log file not found at $log_file"
        return 1
    fi
    
    log "INFO" "Showing DNS query log (Ctrl+C to exit)"
    
    if [ -n "$filter" ]; then
        tail -f "$log_file" | grep --color=auto "$filter"
    else
        tail -f "$log_file"
    fi
    
    return 0
}

# Function to query a domain against blocklists
query_domain() {
    local domain="$1"
    
    # Check if domain is in allowlist
    local is_allowed
    is_allowed=$(db_execute "SELECT COUNT(*) FROM allowlist WHERE domain = '$domain' AND enabled = 1;")
    
    if [ "$is_allowed" -gt 0 ]; then
        log "INFO" "Domain $domain is explicitly allowed (in allowlist)"
        return 0
    fi
    
    # Check if domain is in blocklist
    local is_blocked
    is_blocked=$(db_execute "SELECT COUNT(*) FROM blocklist WHERE domain = '$domain' AND enabled = 1;")
    
    if [ "$is_blocked" -gt 0 ]; then
        log "INFO" "Domain $domain is explicitly blocked (in blocklist)"
        return 0
    fi
    
    # Check if domain matches regex allowlist
    local regex_allow_match
    regex_allow_match=$(db_execute "SELECT regex FROM regex_allowlist WHERE enabled = 1 AND '$domain' REGEXP regex LIMIT 1;")
    
    if [ -n "$regex_allow_match" ]; then
        log "INFO" "Domain $domain matches regex allowlist pattern: $regex_allow_match"
        return 0
    fi
    
    # Check if domain matches regex blocklist
    local regex_block_match
    regex_block_match=$(db_execute "SELECT regex FROM regex_blocklist WHERE enabled = 1 AND '$domain' REGEXP regex LIMIT 1;")
    
    if [ -n "$regex_block_match" ]; then
        log "INFO" "Domain $domain matches regex blocklist pattern: $regex_block_match"
        return 0
    fi
    
    # Check if domain is in gravity database
    local blocklist_match
    blocklist_match=$(db_execute "SELECT bl.url FROM domains d JOIN blocklists bl ON d.blocklist_id = bl.id WHERE d.domain = '$domain' LIMIT 1;")
    
    if [ -n "$blocklist_match" ]; then
        log "INFO" "Domain $domain is blocked by blocklist: $blocklist_match"
        return 0
    fi
    
    log "INFO" "Domain $domain is not blocked"
    return 0
}

# Function to set web password
set_web_password() {
    local password="$1"
    local confirm_password
    
    # If password not provided, prompt for it
    if [ -z "$password" ]; then
        read -s -p "Enter new password (blank for no password): " password
        echo
        
        if [ -z "$password" ]; then
            # Empty password, disable authentication
            set_config_value "web_password" ""
            log "SUCCESS" "Web password removed"
            return 0
        fi
        
        read -s -p "Confirm password: " confirm_password
        echo
        
        if [ "$password" != "$confirm_password" ]; then
            log "ERROR" "Passwords do not match"
            return 1
        fi
    fi
    
    # Hash the password
    local password_hash
    if [[ "$IS_MACOS" == true ]]; then
        # macOS version (doesn't have sha256sum)
        password_hash=$(echo -n "$password" | shasum -a 256 | cut -d' ' -f1)
    else
        # Linux version
        password_hash=$(echo -n "$password" | sha256sum | cut -d' ' -f1)
    fi
    
    # Save the password hash
    set_config_value "web_password" "$password_hash"
    log "SUCCESS" "Web password updated"
    
    return 0
}

# ------- Command Handling -------

show_help() {
    echo "Usage: liohole [options]"
    echo "Network-wide DNS-based content filtering system"
    echo
    echo "Options:"
    echo "  allow DOMAIN      Add domain to allowlist"
    echo "  block DOMAIN      Add domain to blocklist"
    echo "  regex-allow REGEX Add regex pattern to allowlist"
    echo "  regex-block REGEX Add regex pattern to blocklist"
    echo "  rm-allow DOMAIN   Remove domain from allowlist"
    echo "  rm-block DOMAIN   Remove domain from blocklist"
    echo "  allowlist         Show domains in allowlist"
    echo "  blocklist         Show domains in blocklist"
    echo "  add-source URL    Add blocklist source URL"
    echo "  rm-source ID      Remove blocklist source by ID"
    echo "  sources           List blocklist sources"
    echo "  update-gravity    Update blocklist database"
    echo "  enable            Enable LioHole filtering"
    echo "  disable [TIME]    Disable LioHole filtering, optionally for TIME (e.g. 30s, 5m, 2h)"
    echo "  restart-dns       Restart DNS server"
    echo "  reload-dns        Reload DNS server configuration"
    echo "  status            Show LioHole status"
    echo "  tail [FILTER]     Show DNS query log, optionally filtered"
    echo "  query DOMAIN      Check if a domain would be blocked"
    echo "  set-password [PW] Set web interface password"
    echo "  version           Show version information"
    echo "  help              Show this help information"
    echo
    echo "Examples:"
    echo "  liohole allow example.com       # Allow example.com"
    echo "  liohole block badsite.com       # Block badsite.com"
    echo "  liohole disable 30m             # Disable filtering for 30 minutes"
    echo "  liohole query doubleclick.net   # Check if doubleclick.net is blocked"
}

# Handle command line arguments
case "$1" in
    "allow")
        check_privileges "$@"
        if [ -z "$2" ]; then
            log "ERROR" "Missing domain argument"
            exit 1
        fi
        add_to_allowlist "$2" "$3"
        ;;
    "block")
        check_privileges "$@"
        if [ -z "$2" ]; then
            log "ERROR" "Missing domain argument"
            exit 1
        fi
        add_to_blocklist "$2" "$3"
        ;;
    "regex-allow")
        check_privileges "$@"
        if [ -z "$2" ]; then
            log "ERROR" "Missing regex argument"
            exit 1
        fi
        add_regex_to_allowlist "$2" "$3"
        ;;
    "regex-block")
        check_privileges "$@"
        if [ -z "$2" ]; then
            log "ERROR" "Missing regex argument"
            exit 1
        fi
        add_regex_to_blocklist "$2" "$3"
        ;;
    "rm-allow")
        check_privileges "$@"
        if [ -z "$2" ]; then
            log "ERROR" "Missing domain argument"
            exit 1
        fi
        remove_from_allowlist "$2"
        ;;
    "rm-block")
        check_privileges "$@"
        if [ -z "$2" ]; then
            log "ERROR" "Missing domain argument"
            exit 1
        fi
        remove_from_blocklist "$2"
        ;;
    "allowlist")
        list_allowlist
        ;;
    "blocklist")
        list_blocklist
        ;;
    "add-source")
        check_privileges "$@"
        if [ -z "$2" ]; then
            log "ERROR" "Missing URL argument"
            exit 1
        fi
        add_blocklist_source "$2" "$3"
        ;;
    "rm-source")
        check_privileges "$@"
        if [ -z "$2" ]; then
            log "ERROR" "Missing ID argument"
            exit 1
        fi
        remove_blocklist_source "$2"
        ;;
    "sources")
        list_blocklist_sources
        ;;
    "update-gravity")
        check_privileges "$@"
        build_gravity
        ;;
    "enable")
        check_privileges "$@"
        enable_filtering
        ;;
    "disable")
        check_privileges "$@"
        disable_filtering "$2"
        ;;
    "restart-dns")
        check_privileges "$@"
        restart_dns
        ;;
    "reload-dns")
        check_privileges "$@"
        reload_dns
        ;;
    "status")
        show_status
        ;;
    "tail")
        tail_logs "$2"
        ;;
    "query")
        if [ -z "$2" ]; then
            log "ERROR" "Missing domain argument"
            exit 1
        fi
        query_domain "$2"
        ;;
    "set-password")
        check_privileges "$@"
        set_web_password "$2"
        ;;
    "version")
        echo "LioHole version $LIOHOLE_VERSION"
        if [[ "$IS_MACOS" == true ]]; then
            echo "Running on macOS $(sw_vers -productVersion)"
        fi
        ;;
    "help" | "--help" | "-h")
        show_help
        ;;
    *)
        if [ -z "$1" ]; then
            show_help
        else
            log "ERROR" "Unknown command: $1"
            echo
            show_help
            exit 1
        fi
        ;;
esac

exit 0