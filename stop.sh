#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# NTTH Stop Script — Kill ALL services cleanly
# Usage: bash stop.sh
# Automatically detects and tears down gateway mode if active
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"

# ── Gateway-mode constants ────────────────────────────────────────────────────
GW_IFACE="wlx24ec99bfe292"
GW_UPSTREAM="wlp0s20f3"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║        NO TIME TO HACK — Full Shutdown       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── 1. Kill backend (uvicorn on port 8001) ────────────────────────────────────
echo "🔴 Stopping backend..."
sudo fuser -k 8001/tcp 2>/dev/null && echo "   Killed backend on :8001" || echo "   Backend not running"
sudo fuser -k 8000/tcp 2>/dev/null && echo "   Killed process on :8000" || true

# ── 2. Kill honeypot ports ────────────────────────────────────────────────────
echo "🔴 Stopping honeypots..."
for port in 8888 21 23 445 3306 3389 5900 6379 27017 2222 30022; do
  sudo fuser -k ${port}/tcp 2>/dev/null && echo "   Killed :${port}" || true
done

# ── 3. Kill Flutter dev server ────────────────────────────────────────────────
echo "🔴 Stopping Flutter..."
sudo fuser -k 44043/tcp 2>/dev/null && echo "   Killed Flutter on :44043" || echo "   Flutter not running"

# ── 4. Stop Docker containers ────────────────────────────────────────────────
echo "🔴 Stopping Docker containers..."
if command -v docker &>/dev/null; then
  # Stop project-specific containers
  sudo docker stop ntth_defense ntth_cowrie ntth_backend ntth_postgres 2>/dev/null && echo "   Docker containers stopped" || true
  sudo docker rm ntth_defense ntth_cowrie ntth_backend ntth_postgres 2>/dev/null && echo "   Docker containers removed" || true

  # Also try docker compose down (if compose file exists)
  if [ -f "$SCRIPT_DIR/docker-compose.yml" ]; then
    cd "$SCRIPT_DIR"
    sudo docker compose down 2>/dev/null && echo "   docker compose down complete" || true
  fi
  if [ -f "$SCRIPT_DIR/backend/docker-compose.yml" ]; then
    cd "$SCRIPT_DIR/backend"
    sudo docker compose down 2>/dev/null && echo "   backend docker compose down complete" || true
  fi
else
  echo "   Docker not installed — skipping"
fi

# ── 5. Gateway mode teardown (auto-detect) ───────────────────────────────────
GATEWAY_WAS_ACTIVE=false

# Check if hostapd is running on our interface
if systemctl is-active hostapd &>/dev/null; then
  GATEWAY_WAS_ACTIVE=true
fi
if systemctl is-active dnsmasq &>/dev/null; then
  GATEWAY_WAS_ACTIVE=true
fi
if ip -br addr show "$GW_IFACE" 2>/dev/null | grep -q "192.168.4.1/24"; then
  GATEWAY_WAS_ACTIVE=true
fi
if [ -f "$BACKEND_DIR/.env" ] && grep -q "^NETWORK_INTERFACE=$GW_IFACE$" "$BACKEND_DIR/.env"; then
  GATEWAY_WAS_ACTIVE=true
fi

if [ "$GATEWAY_WAS_ACTIVE" = true ]; then
  echo "🔴 Tearing down Gateway mode..."

  # Stop gateway services
  sudo systemctl stop hostapd 2>/dev/null && echo "   Stopped hostapd" || true
  sudo systemctl stop dnsmasq 2>/dev/null && echo "   Stopped dnsmasq" || true
  sudo systemctl reset-failed hostapd dnsmasq 2>/dev/null || true

  # Remove NAT / iptables rules
  sudo iptables -t nat -D POSTROUTING -o "$GW_UPSTREAM" -j MASQUERADE 2>/dev/null && echo "   Removed MASQUERADE rule" || true
  sudo iptables -D FORWARD -i "$GW_IFACE" -o "$GW_UPSTREAM" -j ACCEPT 2>/dev/null && echo "   Removed FORWARD (out) rule" || true
  sudo iptables -D FORWARD -i "$GW_UPSTREAM" -o "$GW_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && echo "   Removed FORWARD (in) rule" || true

  # Flush hotspot interface IP
  sudo ip addr flush dev "$GW_IFACE" 2>/dev/null || true
  sudo ip link set "$GW_IFACE" down 2>/dev/null || true
  sudo nmcli device set "$GW_IFACE" managed yes 2>/dev/null || true
  echo "   Flushed $GW_IFACE"

  # Restore monitor-mode .env if backup exists
  if [ -f "$BACKEND_DIR/.env.monitor-backup" ]; then
    cp "$BACKEND_DIR/.env.monitor-backup" "$BACKEND_DIR/.env"
    echo "   Restored monitor-mode .env"
  fi

  # Restore original dnsmasq config if backup exists
  if [ -f "/etc/dnsmasq.conf.ntth-backup" ]; then
    sudo cp /etc/dnsmasq.conf.ntth-backup /etc/dnsmasq.conf
    echo "   Restored original dnsmasq.conf"
  fi

  echo "   ✅ Gateway mode fully torn down"
else
  # ── 5-alt. Reset AR9271 to managed mode (monitor mode cleanup) ─────────────
  echo "🔴 Resetting AR9271..."
  WIFI_USB=$(iw dev 2>/dev/null | grep -B1 "type monitor" | grep "Interface" | awk '{print $2}' | head -1)
  if [ -n "$WIFI_USB" ]; then
    sudo ip link set "$WIFI_USB" down 2>/dev/null
    sudo iw dev "$WIFI_USB" set type managed 2>/dev/null
    echo "   Reset $WIFI_USB to managed mode"
  else
    echo "   No monitor-mode interfaces found"
  fi
fi

# ── 6. Kill any remaining Python processes for NTTH ──────────────────────────
echo "🔴 Cleaning up stale processes..."
pkill -f "uvicorn app.main:app" 2>/dev/null && echo "   Killed stale uvicorn" || true
sudo pkill -f "uvicorn app.main:app" 2>/dev/null || true

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║         ✅ All services stopped               ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "To restart:"
echo "   Monitor mode:  sudo bash start.sh"
echo "   Gateway mode:  sudo bash start.sh --gateway"
echo ""
