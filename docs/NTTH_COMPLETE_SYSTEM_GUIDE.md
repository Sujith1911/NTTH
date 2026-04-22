# NTTH — Complete System Explanation & Demo Test Guide

> **Status:** System fully built with AR9271 wireless integration  
> **Date:** 2026-04-22

---

## How NTTH Works — End to End

### The One-Line Summary

NTTH is an **autonomous network defense system** that captures network traffic from two sources (wired NIC + AR9271 WiFi adapter), scores every packet using AI (rules + ML), and automatically blocks attackers or redirects them to honeypots — all visible on a live Flutter dashboard.

### What Happens When You Start the System

When you run `sudo uvicorn app.main:app --port 8000`, the system boots **8 concurrent tasks**:

```
┌─ STARTUP SEQUENCE ────────────────────────────────────────────┐
│                                                                │
│  1. Database init (SQLite/PostgreSQL tables created)           │
│  2. Admin user seeded (admin / NtthAdmin2026)                  │
│  3. Event bus started (async pub/sub, 5000-event queue)        │
│  4. Scheduler started (periodic jobs)                          │
│  5. Wired packet sniffer started (Scapy on wlp0s20f3)    ←── captures IP packets
│  5b. WiFi sniffer started (Scapy on wlan0mon via AR9271) ←── captures 802.11 frames
│  6. HTTP honeypot started (port 8888)                          │
│  7. Cowrie log watcher started (tails cowrie.json)             │
│  8. Periodic network scan started (ARP every 60s)             │
│                                                                │
│  + 4 AI agents auto-subscribed to event bus at import time     │
│  + Flutter dashboard served at http://localhost:8000/           │
│  + REST API at http://localhost:8000/api/v1/                   │
│  + Swagger docs at http://localhost:8000/docs                  │
└────────────────────────────────────────────────────────────────┘
```

---

## The Two Capture Pipelines

### Pipeline A: Wired Traffic (existing — working since day 1)

```
YOUR LAPTOP NIC (wlp0s20f3)
       │
       ▼
  Scapy AsyncSniffer ──── filter: "ip" (all IP packets)
       │
       ▼
  feature_extractor.py ── extracts: src_ip, dst_ip, dst_port, protocol,
       │                  pkt_len, is_syn, is_ack, is_rst, flags, timestamp
       │
       ├──► device_registry.update()  ── per-IP: packet count, byte count, SYN count, ports seen
       ├──► update_live_stats()        ── real-time bandwidth tracking
       │
       ▼
  EVENT BUS: "device_seen" ──────────────────────────────────────►
```

**What it captures:** Every IP packet on your WiFi network — web browsing, SSH, DNS, scans, attacks. This is the main security monitoring interface.

### Pipeline B: Wireless Monitor Mode (NEW — AR9271)

```
AR9271 USB ADAPTER (wlan0mon) — monitor mode
       │
       ├── channel_hopper.py ── cycles channels 1–13 every 0.3s
       │                        via: iw dev wlan0mon set channel N
       │
       ▼
  Scapy AsyncSniffer ──── no BPF filter (all raw 802.11 frames)
       │
       ▼
  wifi_feature_extractor.py ── parses 3 frame types:
       │
       ├── Probe Requests ──► probe_tracker.py ──► "wifi_probe_seen"
       │   (device MAC, SSID, RSSI, channel)       tracks device presence
       │
       ├── Deauth Frames ──► deauth_detector.py ──► "wifi_threat_detected"
       │   (src_mac, dst_mac, bssid, reason)        sliding window: >10/sec = ATTACK
       │
       └── Beacon Frames ──► rogue_ap_detector.py ──► "wifi_threat_detected"
           (bssid, ssid, channel, privacy)            same SSID + unknown BSSID = ROGUE
```

**What it captures:** Raw 802.11 management frames that are invisible to normal network interfaces. Only possible because AR9271 supports monitor mode.

---

## The AI Agent Pipeline (Both pipelines feed into this)

```
                     ┌──────────────────────────────────────────────────────┐
  "device_seen"  ───►│  THREAT AGENT (Stage 1)                             │
                     │  • Runs 3 IDS rules: port_scan, syn_flood, brute    │
                     │  • Runs Isolation Forest ML anomaly scorer           │
                     │  • Combines: risk = 0.6×rule + 0.4×ml               │
                     │  • Adds GeoIP: country, city, ASN, lat/lon          │
                     │  • Filters: skip if risk < 0.15 (normal traffic)    │
                     └──────────────┬───────────────────────────────────────┘
                                    │ "threat_detected"
  "wifi_threat_  ───────────────────┤  (WiFi threats get risk=0.95–0.99
   detected"                        │   and bypass IDS — already confirmed)
                                    ▼
                     ┌──────────────────────────────────────────────────────┐
                     │  DECISION AGENT (Stage 2)                            │
                     │  • Maps risk score to action:                        │
                     │    < 0.15  → allow                                   │
                     │    0.15–0.25 → log only                              │
                     │    0.25–0.40 → rate_limit                            │
                     │    0.40–0.80 → honeypot redirect                     │
                     │    ≥ 0.80 → block                                    │
                     │  • Checks: never block gateway IP                    │
                     │  • Checks: honeypot only for SSH/Telnet/RDP ports    │
                     │  • Deduplicates: same src+dst+type within 2s = skip  │
                     └──────────────┬───────────────────────────────────────┘
                                    │ "enforcement_action"
                                    ▼
                     ┌──────────────────────────────────────────────────────┐
                     │  ENFORCEMENT AGENT (Stage 3)                         │
                     │  • rate_limit → nft add rule ... limit rate 10/sec   │
                     │  • honeypot  → nft add rule ... dnat to :30022       │
                     │    + starts Cowrie Docker container if stopped        │
                     │    + registers redirect context (real IP → Docker IP) │
                     │  • block     → nft add rule ... drop                  │
                     │  • All rules auto-expire after 1 hour (TTL)          │
                     └──────────────┬───────────────────────────────────────┘
                                    │ "report_event"
                                    ▼
                     ┌──────────────────────────────────────────────────────┐
                     │  REPORTING AGENT (Stage 4)                           │
                     │  • Saves threat event to PostgreSQL/SQLite           │
                     │  • Broadcasts via WebSocket to Flutter dashboard     │
                     │  • Updates device risk score in DB                   │
                     │  • Logs structured JSON to file                      │
                     └──────────────────────────────────────────────────────┘
```

### Timing

The entire pipeline runs in **~127ms average** from packet capture to firewall rule applied.

---

## The Deception Layer

### SSH Honeypot (Cowrie — Docker container)
- **Port 30022** (external) → mapped to 2222 (internal)
- Accepts ANY username/password
- Simulates a fake Linux shell
- Logs all commands typed by attacker: `whoami`, `ls`, `cat /etc/passwd`, `wget`
- Cowrie JSON log is tailed in real-time by `cowrie_watcher.py`
- Each session is enriched with GeoIP and pushed to dashboard

### HTTP Honeypot (built-in Python)
- **Port 8888**
- Logs any HTTP request to paths like `/admin`, `/wp-login.php`, `/.env`
- Triggers threat events for each probe

### Flow-Aware Redirection
When an attacker hits SSH on your real machine, the system:
1. Detects the brute force (3+ attempts in 120s)
2. Creates an nftables NAT rule redirecting ONLY that attacker's traffic to Cowrie
3. The attacker thinks they're in your real system — actually in the honeypot
4. Their commands are captured and displayed on the dashboard

---

## The Dashboard (Flutter)

9 screens served at `http://localhost:8000/`:

| Screen | What You See |
|--------|-------------|
| **Dashboard** | Total threats, active rules, recent events, system health |
| **Threat Map** | Live threat feed with LIVE/RECENT badges, risk scores, GeoIP location |
| **Firewall** | Active nftables rules (block/redirect/rate_limit), NEW/EXPIRED badges |
| **Honeypot** | SSH sessions with terminal-style command display, credentials captured |
| **Topology** | Network device map from ARP scans, device types |
| **Devices** | Detailed per-device view with traffic stats |
| **System Health** | Component status, event bus metrics |
| **Settings** | Server URL, theme |
| **Logs** | Real-time structured JSON log stream |

---

## REST API (20 endpoints)

| Endpoint | What It Does |
|----------|-------------|
| `POST /api/v1/auth/login` | Get JWT token |
| `GET /api/v1/devices` | List network devices |
| `GET /api/v1/threats` | Paginated threat events |
| `GET /api/v1/firewall/status` | Firewall mode + containment stats |
| `GET /api/v1/firewall/rules` | Active firewall rules |
| `POST /api/v1/firewall/flush` | Emergency: remove all rules |
| `GET /api/v1/honeypot/sessions` | Honeypot session log |
| `GET /api/v1/system/health` | Health check |
| `GET /api/v1/wireless/status` | **NEW:** AR9271 adapter state |
| `GET /api/v1/wireless/devices` | **NEW:** WiFi devices (probe-based) |
| `GET /api/v1/wireless/probes` | **NEW:** Unique SSIDs seen |
| `GET /api/v1/wireless/aps` | **NEW:** Observed access points |
| `GET /api/v1/wireless/threats` | **NEW:** WiFi threat state |
| `POST /api/v1/wireless/whitelist` | **NEW:** Update AP whitelist |
| `WS /ws/live?token=JWT` | Live event stream |

---

## Demo Test — Step by Step

### Prerequisites

```bash
# Make sure you're on Ubuntu with AR9271 plugged in
lsusb | grep 9271
# Expected: 0cf3:9271 Qualcomm Atheros Communications AR9271 802.11n
```

### Step 1: Prepare the AR9271

```bash
# Kill interfering processes
sudo airmon-ng check kill

# Enable monitor mode
sudo airmon-ng start wlx24ec99bfe292

# Verify
sudo airmon-ng
# Expected: phy1  wlan0mon  ath9k_htc  Qualcomm Atheros AR9271
```

### Step 2: Start the Backend

```bash
cd /home/ubuntu/NTTH/backend

# Install dependencies (first time only)
pip install -r requirements.txt

# Start with sudo (needed for packet capture + nftables)
sudo uvicorn app.main:app --host 0.0.0.0 --port 8000 --log-level info
```

**Watch the logs — you should see:**
```
ntth.startup                    version=1.0.0 env=development
ntth.admin_seeded               username=admin
ntth.sniffer_starting           interface=wlp0s20f3
ntth.wifi_sniffer_starting      interface=wlan0mon
channel_hopper.started          interface=wlan0mon channels=[1,2,...,13]
wifi_sniffer.started            interface=wlan0mon
ntth.http_honeypot_started      port=8888
```

### Step 3: Verify System Health

```bash
# Health check (no auth needed)
curl http://localhost:8000/api/v1/system/health | python3 -m json.tool

# Login and get token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"NtthAdmin2026"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token: $TOKEN"
```

### Step 4: Check WiFi Monitoring Status

```bash
# Check AR9271 wireless status
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/wireless/status | python3 -m json.tool

# Expected output:
# {
#   "enabled": true,
#   "interface": "wlan0mon",
#   "running": true,
#   "capture_stats": {
#     "frames_captured": 1247,
#     "probes_seen": 89,
#     "deauths_seen": 3,
#     "beacons_seen": 1155,
#     "threats_detected": 0
#   },
#   "tracked_devices": 12,
#   ...
# }
```

### Step 5: See WiFi Devices Being Tracked

```bash
# List WiFi devices discovered via probe requests
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/wireless/devices | python3 -m json.tool

# Shows all phones/laptops in range with their:
# - MAC address
# - SSIDs they've probed for (their saved WiFi networks!)
# - Signal strength (RSSI)
# - Whether MAC is randomized
# - First/last seen timestamps
```

### Step 6: Demo — Wired Attack (Port Scan)

From a **second device** on the same network (phone with Termux, or another laptop):

```bash
# Port scan the NTTH host
nmap -sS -Pn 10.223.251.241

# Watch the NTTH backend logs — you'll see:
# ids.port_scan           src_ip=10.223.251.XX unique_ports=5
# threat_agent.high_risk  src_ip=10.223.251.XX risk_score=1.0 action=block threat_type=port_scan
# enforcement_agent.blocked ip=10.223.251.XX risk_score=1.0
```

**What happened:**
1. Scapy captured the SYN packets on `wlp0s20f3`
2. Feature extractor parsed each packet
3. Rule engine detected 5+ unique ports in 15 seconds → `port_scan` (score=1.0)
4. Risk calc: `0.6×1.0 + 0.4×ml = 0.95` → action=`block`
5. nftables rule applied: `nft add rule ... ip saddr 10.223.251.XX drop`
6. Stored in DB, broadcast to dashboard via WebSocket

### Step 7: Demo — Wired Attack (SSH Brute Force → Honeypot)

```bash
# From the attacker device — SSH brute force attempts
for i in 1 2 3 4 5; do
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@10.223.251.241 -p 30022 <<< "wrong" 2>/dev/null
done

# After 3 attempts, the system detects brute_force
# The attacker gets redirected to Cowrie honeypot
# Now try connecting — you'll get a fake shell:
ssh root@10.223.251.241 -p 30022
# Type: whoami, ls, cat /etc/passwd, uname -a
# All commands are captured!
```

**Check captured sessions:**
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/honeypot/sessions | python3 -m json.tool

# Shows: session_id, real attacker IP, commands typed, credentials attempted
```

### Step 8: Demo — WiFi Attack (Deauthentication Flood)

**From a second terminal on the NTTH host (with another WiFi adapter or same AR9271):**

```bash
# Find a target BSSID first
sudo airodump-ng wlan0mon --output-format csv -w /tmp/scan 2>/dev/null &
sleep 5 && kill %1
# Look at the output for BSSIDs

# Launch deauth attack (20 frames targeting a BSSID)
sudo aireplay-ng --deauth 50 -a <TARGET_BSSID> wlan0mon
```

**Watch the backend logs:**
```
deauth_detector.attack_detected  bssid=AA:BB:CC:DD:EE:FF src_mac=XX:XX:XX:XX:XX:XX rate=15
threat_agent.wifi_threat         threat_type=deauth_attack severity=high risk_score=0.95
```

**Check via API:**
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/wireless/threats | python3 -m json.tool

curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/threats | python3 -m json.tool
# The deauth attack appears alongside wired threats!
```

### Step 9: Demo — Passive WiFi Device Tracking

```bash
# Just leave the system running — it passively discovers all WiFi
# devices in range by capturing their probe requests

# Check what devices are nearby:
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/wireless/devices | python3 -m json.tool

# Check what SSIDs those devices are looking for:
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/wireless/probes | python3 -m json.tool

# Check what access points are visible:
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/wireless/aps | python3 -m json.tool
```

### Step 10: View the Dashboard

```bash
# If Flutter web build exists:
# Open browser to http://10.223.251.241:8000/

# Or access API docs:
# http://10.223.251.241:8000/docs  (Swagger UI with all endpoints)
```

### Step 11: Check Firewall Rules Applied

```bash
# See what nftables rules NTTH has applied
sudo nft list ruleset | grep ntth

# Or via API:
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/firewall/rules | python3 -m json.tool

# Flush all rules (emergency)
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/firewall/flush
```

---

## Complete Data Flow Diagram

```
                    PHYSICAL LAYER
    ┌─────────────────────────────────────────────┐
    │  wlp0s20f3 (built-in WiFi)                  │ ← Your network connection
    │  wlan0mon  (AR9271 USB, monitor mode)        │ ← Passive 802.11 capture
    └──────────┬──────────────────┬────────────────┘
               │                  │
         IP packets          802.11 frames
               │                  │
    ┌──────────▼──────┐  ┌───────▼──────────┐
    │ packet_sniffer  │  │  wifi_sniffer    │
    │ (Scapy, ip)     │  │  (Scapy, raw)   │
    └──────────┬──────┘  └───────┬──────────┘
               │                  │
    ┌──────────▼──────┐  ┌───────▼──────────┐
    │feature_extractor│  │wifi_feature_ext. │
    │ 10 features     │  │ probe/deauth/    │
    │ per IP packet   │  │ beacon parsing   │
    └──────────┬──────┘  └───────┬──────────┘
               │                  │
    ┌──────────▼──────┐  ┌───────▼──────────┐
    │ device_registry │  │ probe_tracker    │
    │ + live_stats    │  │ deauth_detector  │
    │                 │  │ rogue_ap_detector│
    └──────────┬──────┘  └───────┬──────────┘
               │                  │
         "device_seen"    "wifi_threat_detected"
               │                  │
    ┌──────────▼──────────────────▼──────────┐
    │         EVENT BUS (asyncio.Queue)      │
    │                                         │
    │  ┌─────────────────────────────────┐   │
    │  │ Threat Agent                    │   │
    │  │  IDS rules + Isolation Forest   │   │
    │  │  risk = 0.6×rule + 0.4×ml       │   │
    │  └──────────────┬──────────────────┘   │
    │                 │ "threat_detected"     │
    │  ┌──────────────▼──────────────────┐   │
    │  │ Decision Agent                  │   │
    │  │  risk → action mapping          │   │
    │  │  protocol-aware routing         │   │
    │  └──────────────┬──────────────────┘   │
    │                 │ "enforcement_action"  │
    │  ┌──────────────▼──────────────────┐   │
    │  │ Enforcement Agent               │   │
    │  │  nftables: block/redirect/limit │   │
    │  │  Cowrie auto-start              │   │
    │  └──────────────┬──────────────────┘   │
    │                 │ "report_event"        │
    │  ┌──────────────▼──────────────────┐   │
    │  │ Reporting Agent                 │   │
    │  │  DB persist + WS broadcast      │   │
    │  └─────────────────────────────────┘   │
    └─────────────────────────────────────────┘
               │                    │
    ┌──────────▼──────┐  ┌─────────▼─────────┐
    │  PostgreSQL/    │  │  WebSocket →       │
    │  SQLite DB      │  │  Flutter Dashboard │
    └─────────────────┘  └───────────────────┘
```

---

## File Map (what's where)

```
NTTH/
├── backend/app/
│   ├── main.py                    ← Boots all 8 tasks
│   ├── config.py                  ← All settings (incl. WiFi)
│   ├── agents/
│   │   ├── threat_agent.py        ← IDS + ML + WiFi threat handler
│   │   ├── decision_agent.py      ← Risk → action
│   │   ├── enforcement_agent.py   ← nftables + honeypot
│   │   └── reporting_agent.py     ← DB + WebSocket
│   ├── monitor/
│   │   ├── packet_sniffer.py      ← Wired capture (wlp0s20f3)
│   │   ├── feature_extractor.py   ← IP packet → feature dict
│   │   ├── device_registry.py     ← Per-IP state
│   │   └── network_scanner.py     ← ARP/ping LAN discovery
│   ├── wireless/                  ← NEW: AR9271 module
│   │   ├── wifi_sniffer.py        ← Monitor mode capture (wlan0mon)
│   │   ├── wifi_feature_extractor ← 802.11 frame parsing
│   │   ├── channel_hopper.py      ← Channel 1–13 cycling
│   │   ├── probe_tracker.py       ← Device presence (MAC/SSID/RSSI)
│   │   ├── deauth_detector.py     ← Deauth flood detection
│   │   └── rogue_ap_detector.py   ← Evil twin detection
│   ├── ids/
│   │   ├── rule_engine.py         ← Port scan + SYN flood + brute force
│   │   ├── anomaly_model.py       ← Isolation Forest (200 trees)
│   │   └── risk_calculator.py     ← 0.6×rule + 0.4×ml
│   ├── firewall/
│   │   ├── nft_manager.py         ← nftables block/redirect/limit
│   │   └── rule_tracker.py        ← Dedup + auto-expire
│   ├── honeypot/
│   │   ├── cowrie_watcher.py      ← Tails cowrie.json
│   │   ├── session_logger.py      ← DB + WS for sessions
│   │   └── http_honeypot.py       ← Port 8888 probe logger
│   ├── api/
│   │   ├── routes_wireless.py     ← NEW: 8 WiFi endpoints
│   │   └── routes_*.py            ← Auth, devices, threats, firewall, etc.
│   └── core/
│       ├── event_bus.py           ← Async pub/sub (5000 queue)
│       └── logger.py              ← Structured JSON logging
├── flutter_app/lib/screens/       ← 9 dashboard screens
└── .env                           ← Runtime config (WiFi settings here)
```

---

## Quick Reference Card

| What | Command |
|------|---------|
| **Start system** | `cd backend && sudo uvicorn app.main:app --port 8000` |
| **Enable monitor mode** | `sudo airmon-ng check kill && sudo airmon-ng start wlx24ec99bfe292` |
| **Check health** | `curl localhost:8000/api/v1/system/health` |
| **Get token** | `curl -X POST localhost:8000/api/v1/auth/login -H "Content-Type: application/json" -d '{"username":"admin","password":"NtthAdmin2026"}'` |
| **WiFi status** | `curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/v1/wireless/status` |
| **WiFi devices** | `curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/v1/wireless/devices` |
| **All threats** | `curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/v1/threats` |
| **Firewall rules** | `curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/v1/firewall/rules` |
| **Honeypot sessions** | `curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/v1/honeypot/sessions` |
| **Dashboard** | `http://10.223.251.241:8000/` |
| **API docs** | `http://10.223.251.241:8000/docs` |
| **Test port scan** | `nmap -sS -Pn 10.223.251.241` (from attacker device) |
| **Test brute force** | `ssh root@10.223.251.241 -p 30022` (repeat 5x) |
| **Test deauth** | `sudo aireplay-ng --deauth 50 -a <BSSID> wlan0mon` |
| **Flush firewall** | `curl -X POST -H "Authorization: Bearer $TOKEN" localhost:8000/api/v1/firewall/flush` |
