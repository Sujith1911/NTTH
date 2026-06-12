#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# NTTH Startup Script — NO TIME TO HACK
# Usage:
#   sudo bash start.sh              # Monitor mode (original)
#   sudo bash start.sh --gateway    # Gateway/Hotspot mode (recommended)
# ──────────────────────────────────────────────────────────────────────────────
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FLUTTER_DIR="$SCRIPT_DIR/flutter_app"
GATEWAY_DIR="$SCRIPT_DIR/scripts/gateway"
VENV="$BACKEND_DIR/venv"
BACKEND_PORT=8001

# ── Parse mode ────────────────────────────────────────────────────────────────
NTTH_MODE="monitor"
if [[ "$1" == "--gateway" ]] || [[ "$NTTH_MODE_ENV" == "gateway" ]]; then
  NTTH_MODE="gateway"
fi

# ── Gateway-mode constants ────────────────────────────────────────────────────
GW_IFACE="wlx24ec99bfe292"       # USB adapter (hotspot)
GW_UPSTREAM="wlp0s20f3"          # Built-in Wi-Fi (internet)
GW_IP="192.168.4.1"
GW_SUBNET="192.168.4.0/24"
BRIDGE_MAC="02:4e:54:54:48:01"  # Stable gateway MAC; TAP ports must not change it

echo ""
echo "╔══════════════════════════════════════════════╗"
if [ "$NTTH_MODE" = "gateway" ]; then
echo "║    NO TIME TO HACK — Gateway Mode  🛡️        ║"
else
echo "║    NO TIME TO HACK — Monitor Mode  📡        ║"
fi
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── 1. Create venv if missing ─────────────────────────────────────────────────
if [ ! -f "$VENV/bin/activate" ]; then
  echo "📦 Creating virtual environment..."
  python3 -m venv "$VENV"
  echo "✅ Venv created"
fi

# ── 2. Install dependencies ───────────────────────────────────────────────────
echo "📦 Installing/checking Python dependencies..."
"$VENV/bin/pip" install -q -r "$BACKEND_DIR/requirements.txt" \
  && echo "✅ Dependencies OK" \
  || echo "⚠️  pip had warnings (continuing)"

# ── 3. Kill ALL old processes ─────────────────────────────────────────────────
echo ""
echo "🔍 Cleaning up old processes..."

# Backend port
sudo fuser -k "${BACKEND_PORT}/tcp" 2>/dev/null && echo "   ⚠️ Killed old backend on :$BACKEND_PORT" || echo "   ✅ Port $BACKEND_PORT is free"
sudo fuser -k 8000/tcp 2>/dev/null || true
sleep 1

# Honeypot ports
for port in 8888 21 23 445 3306 3389 5900 6379 27017 2222 30022; do
  sudo fuser -k ${port}/tcp 2>/dev/null || true
done
echo "   ✅ Honeypot ports cleared"

# Stale uvicorn
sudo pkill -f "uvicorn app.main:app" 2>/dev/null || true

# ── 4. Stop old Docker containers ────────────────────────────────────────────
echo ""
echo "🐳 Checking Docker..."
if command -v docker &>/dev/null; then
  sudo docker stop ntth_defense ntth_cowrie ntth_backend ntth_postgres 2>/dev/null || true
  sudo docker rm ntth_defense ntth_cowrie ntth_backend ntth_postgres 2>/dev/null || true
  echo "   ✅ Docker containers cleared"

  echo "   🐝 Starting Cowrie SSH honeypot..."
  mkdir -p "$BACKEND_DIR/cowrie/logs"
  sudo chmod 777 "$BACKEND_DIR/cowrie/logs" 2>/dev/null || true
  if sudo docker compose -f "$BACKEND_DIR/docker-compose.yml" up -d cowrie; then
    echo "   ✅ Cowrie ready on :30022"
  else
    echo "   ⚠️ Cowrie did not start; backend will retry via controller"
  fi
else
  echo "   ⚠️ Docker not installed — skipping"
fi

# ══════════════════════════════════════════════════════════════════════════════
# ── 5. MODE-SPECIFIC SETUP ───────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

if [ "$NTTH_MODE" = "gateway" ]; then
  # ────────────────────────────────────────────────────────────────────────────
  # GATEWAY MODE — USB adapter runs as Access Point
  # ────────────────────────────────────────────────────────────────────────────
  echo ""
  echo "🛡️  Setting up Gateway / Hotspot mode..."

  # ── 5pre. Validate interfaces before touching gateway services ────────────
  if ! ip link show "$GW_UPSTREAM" &>/dev/null; then
    echo "   ❌ Upstream interface not found: $GW_UPSTREAM"
    echo "      Check with: ip -br addr"
    exit 1
  fi

  if ! ip link show "$GW_IFACE" &>/dev/null; then
    echo "   ❌ Hotspot interface not found: $GW_IFACE"
    echo "      Plug in the USB Wi-Fi adapter, then check:"
    echo "        lsusb"
    echo "        iw dev"
    exit 1
  fi

  if ! iw list 2>/dev/null | grep -q "^[[:space:]]*\\* AP$"; then
    echo "   ❌ No Wi-Fi adapter reports AP mode support"
    echo "      Check with: iw list | grep -A 10 'Supported interface modes'"
    exit 1
  fi

  # ── 5a. Check required packages ────────────────────────────────────────────
  MISSING_PKGS=""
  for pkg in hostapd dnsmasq; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
      MISSING_PKGS="$MISSING_PKGS $pkg"
    fi
  done
  if [ -n "$MISSING_PKGS" ]; then
    echo "   📦 Installing missing packages:$MISSING_PKGS"
    sudo apt update -qq
    sudo apt install -y -qq $MISSING_PKGS
  fi

  # ── 5b. Stop any conflicting services ──────────────────────────────────────
  sudo systemctl stop hostapd 2>/dev/null || true
  sudo systemctl stop dnsmasq 2>/dev/null || true

  # ── 5c. Ensure adapter is in managed mode (not monitor) ────────────────────
  echo "   📡 Configuring $GW_IFACE for AP mode..."
  sudo nmcli device disconnect "$GW_IFACE" 2>/dev/null || true
  sudo nmcli device set "$GW_IFACE" managed no 2>/dev/null || true
  sudo rfkill unblock wifi 2>/dev/null || true
  CURRENT_MODE=$(iw dev "$GW_IFACE" info 2>/dev/null | grep "type" | awk '{print $2}')
  if [ "$CURRENT_MODE" = "monitor" ]; then
    echo "   🔧 Switching from monitor → managed mode..."
    sudo ip link set "$GW_IFACE" down
    sudo iw dev "$GW_IFACE" set type managed
  fi

  # ── 5d. Create bridge and assign gateway IP ─────────────────────────────────
  BRIDGE="br-ntth"
  if ! ip link show "$BRIDGE" &>/dev/null; then
    sudo ip link add name "$BRIDGE" type bridge
    echo "   ✅ Bridge $BRIDGE created"
  else
    echo "   ✅ Bridge $BRIDGE already exists"
  fi
  sudo ip link set dev "$BRIDGE" address "$BRIDGE_MAC"
  sudo ip addr flush dev "$GW_IFACE" 2>/dev/null || true
  sudo ip addr flush dev "$BRIDGE" 2>/dev/null || true
  sudo ip addr add "$GW_IP/24" dev "$BRIDGE"
  sudo ip link set "$BRIDGE" up
  sudo ip link set "$GW_IFACE" up
  sudo ip link set "$BRIDGE" promisc on
  echo "   ✅ $BRIDGE → $GW_IP/24 (bridge mode, promisc on)"

  # ── 5e. Deploy hostapd config ──────────────────────────────────────────────
  if [ -f "$GATEWAY_DIR/hostapd.conf" ]; then
    sudo cp "$GATEWAY_DIR/hostapd.conf" /etc/hostapd/hostapd.conf
    echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' | sudo tee /etc/default/hostapd > /dev/null
    echo "   ✅ hostapd.conf deployed"
  else
    echo "   ❌ Missing $GATEWAY_DIR/hostapd.conf — cannot continue"
    exit 1
  fi

  # ── 5f. Deploy dnsmasq config ──────────────────────────────────────────────
  if [ -f "$GATEWAY_DIR/dnsmasq.conf" ]; then
    # Back up existing config
    sudo cp /etc/dnsmasq.conf /etc/dnsmasq.conf.ntth-backup 2>/dev/null || true
    sudo cp "$GATEWAY_DIR/dnsmasq.conf" /etc/dnsmasq.conf
    echo "   ✅ dnsmasq.conf deployed"
  else
    echo "   ❌ Missing $GATEWAY_DIR/dnsmasq.conf — cannot continue"
    exit 1
  fi

  # ── 5g. Enable IP forwarding ───────────────────────────────────────────────
  echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
  echo "   ✅ IP forwarding enabled"

  # ── 5g2. Enable bridge netfilter so nftables DNAT applies to bridged traffic
  #          (VM-to-VM traffic is switched at layer 2; without br_netfilter,
  #           nftables prerouting hooks never see it and DNAT rules are ignored)
  sudo modprobe br_netfilter 2>/dev/null || true
  if [ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
    echo 1 | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables > /dev/null
    echo "   ✅ Bridge netfilter enabled (nftables DNAT works on bridged traffic)"
  fi

  # ── 5h. Set up NAT / iptables ──────────────────────────────────────────────
  # Flush old NTTH rules first (idempotent)
  sudo iptables -t nat -D POSTROUTING -o "$GW_UPSTREAM" -j MASQUERADE 2>/dev/null || true
  sudo iptables -D FORWARD -i "$BRIDGE" -o "$GW_UPSTREAM" -j ACCEPT 2>/dev/null || true
  sudo iptables -D FORWARD -i "$GW_UPSTREAM" -o "$BRIDGE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  sudo iptables -D FORWARD -i "$BRIDGE" -o "$BRIDGE" -j ACCEPT 2>/dev/null || true
  sudo iptables -D INPUT -i "$BRIDGE" -p udp --dport 67 -j ACCEPT 2>/dev/null || true
  sudo iptables -D INPUT -i "$BRIDGE" -p udp --dport 68 -j ACCEPT 2>/dev/null || true
  # Clean up any old rules referencing the raw Wi-Fi iface
  sudo iptables -D FORWARD -i "$GW_IFACE" -o "$GW_UPSTREAM" -j ACCEPT 2>/dev/null || true
  sudo iptables -D FORWARD -i "$GW_UPSTREAM" -o "$GW_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

  # Intra-bridge: allow VMs to talk to each other and to dnsmasq (DHCP)
  sudo iptables -I FORWARD -i "$BRIDGE" -o "$BRIDGE" -j ACCEPT
  sudo iptables -I INPUT -i "$BRIDGE" -p udp --dport 67 -j ACCEPT
  sudo iptables -I INPUT -i "$BRIDGE" -p udp --dport 68 -j ACCEPT
  # Forward from bridge to upstream (internet access for VMs)
  sudo iptables -t nat -A POSTROUTING -o "$GW_UPSTREAM" -j MASQUERADE
  sudo iptables -A FORWARD -i "$BRIDGE" -o "$GW_UPSTREAM" -j ACCEPT
  sudo iptables -A FORWARD -i "$GW_UPSTREAM" -o "$BRIDGE" -m state --state RELATED,ESTABLISHED -j ACCEPT
  echo "   ✅ NAT + bridge forwarding rules applied"

  # ── 5h2. Initialise NTTH nftables infrastructure ──────────────────────────
  # Create NTTH-owned tables/chains for security rules (containment, redirect)
  sudo nft add table inet ntth_filter 2>/dev/null || true
  sudo nft add chain inet ntth_filter ntth_input '{ type filter hook input priority 0; }' 2>/dev/null || true
  sudo nft add chain inet ntth_filter ntth_forward '{ type filter hook forward priority -10; }' 2>/dev/null || true
  sudo nft add table ip ntth_nat 2>/dev/null || true
  sudo nft add chain ip ntth_nat ntth_prerouting '{ type nat hook prerouting priority dstnat; }' 2>/dev/null || true
  echo "   ✅ nftables NTTH infrastructure ready"

  # ── 5i. Switch backend .env to gateway mode ────────────────────────────────
  if [ -f "$GATEWAY_DIR/env.gateway" ]; then
    # Back up current .env
    cp "$BACKEND_DIR/.env" "$BACKEND_DIR/.env.monitor-backup" 2>/dev/null || true
    cp "$GATEWAY_DIR/env.gateway" "$BACKEND_DIR/.env"
    echo "   ✅ Backend .env switched to gateway mode"
  fi

  # ── 5j. Start hostapd & dnsmasq ────────────────────────────────────────────
  sudo systemctl unmask hostapd 2>/dev/null || true
  sudo systemctl reset-failed hostapd dnsmasq 2>/dev/null || true
  sudo systemctl restart hostapd
  sudo systemctl restart dnsmasq
  echo "   ✅ hostapd started (SSID: NTTH-Secure)"
  echo "   ✅ dnsmasq started (DHCP: 192.168.4.2–100)"

  # ── 5k. Verify gateway is operational ──────────────────────────────────────
  echo ""
  echo "   🔍 Gateway verification:"
  HOSTAPD_STATUS=$(systemctl is-active hostapd 2>/dev/null)
  DNSMASQ_STATUS=$(systemctl is-active dnsmasq 2>/dev/null)
  echo "      hostapd:  $HOSTAPD_STATUS"
  echo "      dnsmasq:  $DNSMASQ_STATUS"
  echo "      IP fwd:   $(cat /proc/sys/net/ipv4/ip_forward)"
  echo "      Gateway:  $GW_IP on $GW_IFACE"
  echo "      Upstream: $GW_UPSTREAM"
  AP_MODE=$(iw dev "$GW_IFACE" info 2>/dev/null | awk '/type/ {print $2}')
  echo "      Wi-Fi:    ${AP_MODE:-unknown}"

  if [ "$HOSTAPD_STATUS" != "active" ]; then
    echo ""
    echo "   ❌ hostapd failed to start! Check: sudo journalctl -u hostapd -n 20"
    echo "      Common fix: make sure no other process is using $GW_IFACE"
    exit 1
  fi
  if [ "$AP_MODE" != "AP" ]; then
    echo ""
    echo "   ❌ $GW_IFACE is not in AP mode; real devices will disconnect."
    echo "      Check: sudo journalctl -u hostapd -n 30"
    echo "      The script marked $GW_IFACE unmanaged in NetworkManager so hostapd can own it."
    exit 1
  fi

else
  # ────────────────────────────────────────────────────────────────────────────
  # MONITOR MODE — USB adapter in monitor mode (original behavior)
  # ────────────────────────────────────────────────────────────────────────────
  echo ""
  echo "📡 Scanning for WiFi adapter..."

  # Find USB wireless adapter (wlx prefix = USB)
  USB_IFACE=""
  for iface in $(iw dev 2>/dev/null | grep "Interface" | awk '{print $2}'); do
    if [[ "$iface" == wlx* ]]; then
      USB_IFACE="$iface"
      break
    fi
  done

  if [ -n "$USB_IFACE" ]; then
    echo "   ✅ AR9271 found: $USB_IFACE"

    # Check if already in monitor mode
    MODE=$(iw dev "$USB_IFACE" info 2>/dev/null | grep "type" | awk '{print $2}')
    if [ "$MODE" = "monitor" ]; then
      echo "   ✅ Already in monitor mode"
    else
      echo "   🔧 Switching to monitor mode..."
      sudo nmcli device disconnect "$USB_IFACE" 2>/dev/null || true
      sudo ip link set "$USB_IFACE" down
      sudo iw dev "$USB_IFACE" set type monitor
      sudo ip link set "$USB_IFACE" up
      echo "   ✅ Monitor mode active on $USB_IFACE"
    fi
  else
    echo "   ⚠️ No USB WiFi adapter found. Plug in AR9271 and restart."
  fi

  # Show all WiFi interfaces
  echo ""
  echo "   All WiFi interfaces:"
  iw dev 2>/dev/null | grep -E "Interface|type" | sed 's/^/      /'
fi

# ── 6. Start Backend ─────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════"
echo "🚀 Starting NTTH backend on :$BACKEND_PORT"
if [ "$NTTH_MODE" = "gateway" ]; then
echo "   Mode      → GATEWAY (Hotspot AP)"
echo "   Dashboard → http://192.168.4.1:$BACKEND_PORT"
echo "   Protected → Connect to NTTH-Secure Wi-Fi"
else
echo "   Mode      → MONITOR (Passive)"
echo "   Dashboard → http://localhost:$BACKEND_PORT"
fi
echo "   API Docs  → http://localhost:$BACKEND_PORT/docs"
echo "   Health    → http://localhost:$BACKEND_PORT/api/v1/system/health"
echo "═══════════════════════════════════════════════"
echo ""

cd "$BACKEND_DIR"
exec sudo "$VENV/bin/uvicorn" app.main:app \
  --host 0.0.0.0 \
  --port $BACKEND_PORT \
  --reload \
  --log-level info
