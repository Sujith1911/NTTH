# NTTH — Physical Ubuntu Deployment Guide

> This guide is for deploying NTTH on a **physical Ubuntu machine** (laptop, desktop, mini-PC).
> The project directory has been copied from Windows, so all source code is already present.

---

## Pre-Requisites

- Physical machine with Ubuntu Server 24.04 LTS installed
- Internet connection (Ethernet or WiFi)
- NTTH project directory copied to the machine (e.g., `/home/<user>/NTTH/`)

---

## File Integrity Checklist

Before starting, verify your critical files are present:

```bash
cd ~/NTTH

# Quick check — should print all paths without errors
ls backend/app/main.py \
   backend/app/config.py \
   backend/app/agents/threat_agent.py \
   backend/app/agents/decision_agent.py \
   backend/app/agents/enforcement_agent.py \
   backend/app/agents/reporting_agent.py \
   backend/app/ids/rule_engine.py \
   backend/app/ids/anomaly_model.py \
   backend/app/monitor/packet_sniffer.py \
   backend/app/monitor/network_scanner.py \
   backend/app/firewall/nft_manager.py \
   backend/app/honeypot/cowrie_watcher.py \
   backend/app/honeypot/http_honeypot.py \
   backend/app/honeypot/session_logger.py \
   backend/app/core/event_bus.py \
   backend/app/database/models.py \
   backend/app/database/crud.py \
   backend/docker-compose.yml \
   backend/Dockerfile \
   backend/requirements.txt \
   backend/.env.example \
   backend/cowrie/cowrie.cfg \
   flutter_app/lib/main.dart \
   flutter_app/pubspec.yaml \
   flutter_app/pubspec.lock

# Count all backend Python files (should be ~40)
find backend/app -name "*.py" | wc -l

# Count Flutter Dart files (should be ~21)
find flutter_app/lib -name "*.dart" | wc -l
```

---

## Step 1: Install All Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y

# Core packages
sudo apt install -y \
  curl wget git unzip net-tools vim htop \
  python3 python3-pip python3-venv \
  nftables iptables-persistent \
  openssh-server postgresql-client \
  dnsmasq nmap tcpdump

# Docker (official method)
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

# Add user to docker group
sudo usermod -aG docker $USER

# Flutter
sudo snap install flutter --classic

# Enable services
sudo systemctl enable docker && sudo systemctl start docker
sudo systemctl enable ssh && sudo systemctl start ssh
sudo systemctl enable nftables && sudo systemctl start nftables

# IMPORTANT: Log out and back in for docker group
exit
```

Log back in, then verify:
```bash
docker ps          # Should show empty table, no permission error
flutter --version  # Should show Flutter version
nft list tables    # Should not error
```

---

## Step 2: Identify Your Network Interfaces

```bash
ip a
```

You'll see your interfaces. Common names:

| Physical Hardware | Typical Name | Role |
|---|---|---|
| Ethernet port | `eth0`, `enp0s3`, `eno1` | Internet |
| WiFi adapter | `wlan0`, `wlp2s0` | Hotspot OR Internet |
| USB Ethernet | `enxXXXXXXXXXXXX` | Internet |

**Write down your interface names.** Replace `INTERNET_IF` and `PROTECTED_IF` in all commands below.

---

## Step 3: Choose Your Network Mode

### Mode A: Two NICs (Ethernet + WiFi AP)

Best for full protection. One NIC for internet, WiFi creates hotspot.

```
Internet ──→ [eth0] UBUNTU [wlan0 AP: "NTTH-Secure"] ──→ All devices
```

### Mode B: Single NIC (Same Network as All Devices)

Simpler. Ubuntu and all devices on the same network (e.g., home WiFi).
NTTH catches attacks aimed at Ubuntu. Good for demo.

```
Home WiFi / Mobile Hotspot
    ├── Ubuntu (NTTH)
    ├── Kali (attacker)
    ├── Phone (dashboard viewer)
    └── Laptop (dashboard viewer)
```

### Mode C: VirtualBox Internal Network (from VM setup)

Ubuntu has `enp0s8` on an Internal Network. VMs connect to it.

```
Hotspot ──→ [enp0s3] UBUNTU [enp0s8: 192.168.4.1] ──→ Kali VM, Victim VM
```

---

## Step 4A: Setup for Mode A (WiFi Hotspot — Full Protection)

### Check WiFi supports AP mode:
```bash
iw list | grep -A 5 "Supported interface modes"
# Must show "AP" in the list
```

### Install and configure hostapd:
```bash
sudo apt install -y hostapd

sudo nano /etc/hostapd/hostapd.conf
```

```ini
# Replace wlan0 with YOUR WiFi interface name
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

```bash
sudo nano /etc/default/hostapd
# Add this line:
# DAEMON_CONF="/etc/hostapd/hostapd.conf"
```

### Configure networking:
```bash
# Replace eth0/wlan0 with YOUR interface names
sudo nano /etc/netplan/01-ntth.yaml
```

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:                    # ← YOUR internet interface
      dhcp4: true
  wifis:
    wlan0:                   # ← YOUR WiFi interface
      dhcp4: false
      addresses:
        - 192.168.4.1/24
```

```bash
sudo chmod 600 /etc/netplan/01-ntth.yaml
sudo netplan apply
```

### Enable routing + NAT:
```bash
# IP forwarding
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# NAT — replace eth0 and wlan0 with YOUR interface names
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
sudo netfilter-persistent save
```

### DHCP server:
```bash
# Fix DNS port conflict
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo rm /etc/resolv.conf
echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" | sudo tee /etc/resolv.conf

# Configure DHCP — replace wlan0 with YOUR interface
sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
sudo nano /etc/dnsmasq.conf
```

```ini
interface=wlan0
dhcp-range=192.168.4.2,192.168.4.100,255.255.255.0,24h
server=8.8.8.8
server=8.8.4.4
```

### Start everything:
```bash
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl start hostapd
sudo systemctl enable dnsmasq
sudo systemctl restart dnsmasq
```

### Verify:
```bash
sudo systemctl status hostapd    # active (running)
sudo systemctl status dnsmasq    # active (running)
ip a show wlan0                  # inet 192.168.4.1/24
cat /proc/sys/net/ipv4/ip_forward  # 1
```

### .env settings for Mode A:
```bash
NETWORK_INTERFACE=wlan0
GATEWAY_IP=192.168.4.1
SCAN_SUBNET=192.168.4.0/24
SERVER_DISPLAY_IP=192.168.4.1
```

---

## Step 4B: Setup for Mode B (Same Network — Simple Demo)

No extra network config needed. Just find Ubuntu's IP:

```bash
ip a
# Note the IP on your connected interface (e.g., 192.168.1.50 or 10.142.204.2)
```

### .env settings for Mode B:
```bash
# Replace with YOUR interface name and IP
NETWORK_INTERFACE=eth0
GATEWAY_IP=192.168.1.1
SCAN_SUBNET=192.168.1.0/24
SERVER_DISPLAY_IP=192.168.1.50
```

---

## Step 4C: Setup for Mode C (VirtualBox Internal Network)

Already configured if coming from the VM setup. Same as Mode A but with `enp0s8`.

### .env settings for Mode C:
```bash
NETWORK_INTERFACE=enp0s8
GATEWAY_IP=192.168.4.1
SCAN_SUBNET=192.168.4.0/24
SERVER_DISPLAY_IP=192.168.4.1
```

---

## Step 5: Create .env File

```bash
cd ~/NTTH/backend
cp .env.example .env
nano .env
```

**Full .env template** (fill in values from your chosen Mode above):
```bash
# App
ENVIRONMENT=development
DEBUG=true

# Security — CHANGE THESE
SECRET_KEY=your-random-secret-key-here
ADMIN_PASSWORD=your-admin-password

# Network — FROM YOUR CHOSEN MODE ABOVE
NETWORK_INTERFACE=<your-interface>
GATEWAY_IP=<your-gateway-ip>
SCAN_SUBNET=<your-subnet>
SERVER_DISPLAY_IP=<ubuntu-ip>

# Database
POSTGRES_DB=ntth
POSTGRES_USER=ntth_user
POSTGRES_PASSWORD=your-db-password

# Firewall
FIREWALL_ENABLED=true
COWRIE_REDIRECT_PORT=30022
COWRIE_CONTAINER_NAME=ntth_cowrie
```

---

## Step 6: Build Flutter Web App

```bash
cd ~/NTTH/flutter_app
flutter pub get
flutter build web
```

Wait for `✓ Built build/web`.

---

## Step 7: Fix Docker iptables (If Needed)

```bash
sudo modprobe ip_tables
sudo modprobe iptable_filter
sudo modprobe iptable_nat
sudo systemctl restart docker
```

---

## Step 8: Deploy

```bash
cd ~/NTTH/backend
docker compose up -d --build
```

First run takes 5-10 minutes (pulls PostgreSQL, Cowrie, builds backend).

### Verify:
```bash
# All 3 containers running
docker ps
# Expected: ntth_backend, ntth_postgres, ntth_cowrie

# Backend logs
docker compose logs backend --tail 30
# Look for: ntth.startup, sniffer, honeypot

# Cowrie logs
docker compose logs cowrie --tail 10
```

---

## Step 9: Access Dashboard

From any device on the same network:

```
http://<ubuntu-ip>:8000
```

Login: `admin` / `<your ADMIN_PASSWORD from .env>`

---

## Step 10: Test

### From any device on the network:
```bash
# Port scan Ubuntu
nmap -sS -Pn <ubuntu-ip>

# SSH to honeypot
ssh root@<ubuntu-ip>

# HTTP honeypot
curl http://<ubuntu-ip>:8888/admin
```

### Verify in database:
```bash
docker exec ntth_postgres psql -U ntth_user -d ntth -c \
  "SELECT src_ip, threat_type, risk_score, action_taken FROM threat_events ORDER BY detected_at DESC LIMIT 10;"
```

---

## Quick Deploy Script

Create `~/deploy.sh` for easy redeployment after code changes:

```bash
#!/bin/bash
set -e
echo "=== Pulling latest code ==="
cd ~/NTTH
git pull origin main 2>/dev/null || echo "Not a git repo, skipping pull"

echo "=== Building Flutter web ==="
cd flutter_app
flutter pub get
flutter build web

echo "=== Deploying Docker stack ==="
cd ../backend
docker compose down
docker compose up -d --build

echo "=== Waiting for startup ==="
sleep 10

echo "=== Container status ==="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "✅ NTTH deployed! Dashboard: http://$(hostname -I | awk '{print $1}'):8000"
```

```bash
chmod +x ~/deploy.sh
# Usage: ~/deploy.sh
```

---

## Auto-Start on Boot

```bash
sudo nano /opt/ntth-startup.sh
```

```bash
#!/bin/bash
sleep 15
cd /home/<your-username>/NTTH/backend
docker compose up -d
```

```bash
sudo chmod +x /opt/ntth-startup.sh
sudo crontab -e
# Add:
@reboot /opt/ntth-startup.sh
```

---

## Stopping / Restarting

```bash
# Stop everything
cd ~/NTTH/backend
docker compose down

# Restart
docker compose up -d

# Rebuild after code changes
docker compose down
docker compose up -d --build

# View logs live
docker compose logs -f backend

# Emergency: flush all firewall rules
docker exec ntth_backend python3 -c "
import asyncio
from app.firewall.nft_manager import NFTManager
asyncio.run(NFTManager().flush_chain())
print('Flushed')
"
```

---

## Troubleshooting

### Docker compose fails with iptables error
```bash
sudo modprobe ip_tables && sudo modprobe iptable_filter && sudo modprobe iptable_nat
sudo update-alternatives --set iptables /usr/sbin/iptables-legacy
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
sudo systemctl restart docker
```

### dnsmasq fails (port 53 in use)
```bash
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo rm /etc/resolv.conf
echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" | sudo tee /etc/resolv.conf
sudo systemctl restart dnsmasq
```

### Can't reach dashboard from other devices
```bash
# Check backend is running
docker ps | grep ntth_backend

# Check which port it's on
docker compose logs backend | grep "8000"

# Check Ubuntu's firewall isn't blocking
sudo ufw status
# If active, allow port 8000:
sudo ufw allow 8000
sudo ufw allow 8888
sudo ufw allow 30022
```

### Sniffer not capturing packets
```bash
# Check interface exists and is UP
ip a show <your-interface>

# Check Docker has NET_ADMIN capability
docker inspect ntth_backend | grep -A 5 "CapAdd"

# Check manually
docker exec ntth_backend python3 -c "
from scapy.all import get_if_list
print(get_if_list())
"
```

### Flutter build fails
```bash
# Clean and rebuild
cd ~/NTTH/flutter_app
flutter clean
flutter pub get
flutter build web
```

---

## Directory Structure Reference

```
NTTH/
├── backend/
│   ├── app/
│   │   ├── agents/           # 4 AI agents (threat, decision, enforcement, reporting)
│   │   ├── api/              # 7 REST API route files
│   │   ├── core/             # Event bus, scheduler, logger, security
│   │   ├── database/         # ORM models, CRUD, schemas, session
│   │   ├── firewall/         # nftables manager, rule tracker, cleanup
│   │   ├── geoip/            # MaxMind GeoIP lookup
│   │   ├── honeypot/         # Cowrie controller, watcher, HTTP honeypot, session logger
│   │   ├── ids/              # Rule engine, anomaly model, risk calculator
│   │   ├── monitor/          # Packet sniffer, network scanner, device registry
│   │   ├── websocket/        # Live WebSocket broadcaster
│   │   ├── config.py         # All settings (env-driven)
│   │   ├── dependencies.py   # FastAPI DI (auth, DB)
│   │   └── main.py           # App factory + lifespan
│   ├── cowrie/               # Cowrie SSH honeypot config
│   ├── geoip/                # GeoLite2 .mmdb files (download separately)
│   ├── docker-compose.yml    # 3-service stack
│   ├── Dockerfile            # Backend container image
│   ├── .env.example          # Environment template
│   ├── ntth.service          # systemd unit (bare-metal alternative)
│   └── requirements.txt      # Python dependencies
├── flutter_app/
│   ├── lib/
│   │   ├── core/             # API client, auth, WebSocket, settings
│   │   ├── models/           # Device, threat, firewall, honeypot models
│   │   ├── screens/          # 9 screens (dashboard, devices, threats, firewall, honeypot, topology, system, settings, login)
│   │   ├── theme/            # App theme + provider
│   │   ├── widgets/          # Reusable widgets (drawer, tiles, cards)
│   │   └── main.dart         # App entry point
│   ├── pubspec.yaml          # Flutter dependencies
│   └── pubspec.lock          # Locked dependency versions
├── docs/
│   ├── walkthrough/          # 19 documentation files
│   └── KALI_ATTACK_TEST_RUNBOOK.md
├── scripts/                  # Windows dev scripts
├── Makefile                  # Build/deploy commands
└── README.md                 # Project overview
```
