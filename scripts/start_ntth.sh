#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────
# NTTH — Auto-Start Script
# Detects AR9271, enables monitor mode, starts NTTH backend
# ────────────────────────────────────────────────────────────────
# Usage:
#   sudo ./scripts/start_ntth.sh            # Normal start
#   sudo ./scripts/start_ntth.sh --no-wifi  # Skip wireless
#   sudo ./scripts/start_ntth.sh --dev      # Dev mode with reload
# ────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[NTTH]${NC} $*"; }
ok()   { echo -e "${GREEN}  ✅ $*${NC}"; }
warn() { echo -e "${YELLOW}  ⚠️  $*${NC}"; }
err()  { echo -e "${RED}  ❌ $*${NC}"; }

SKIP_WIFI=false
DEV_MODE=false
PORT=8000

for arg in "$@"; do
    case "$arg" in
        --no-wifi)  SKIP_WIFI=true ;;
        --dev)      DEV_MODE=true ;;
        --port=*)   PORT="${arg#*=}" ;;
    esac
done

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     NTTH — No Time To Hack                              ║"
echo "║     Autonomous AI-Driven Honeypot Firewall               ║"
echo "║     $(date '+%Y-%m-%d %H:%M:%S')                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Root check ──
if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (sudo)"
    echo "  Usage: sudo $0"
    exit 1
fi
ok "Running as root"

# ── Step 2: Find project directory ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Handle both /NTTH/scripts/ and /app/ (Docker) paths
if [ -f "$SCRIPT_DIR/../backend/app/main.py" ]; then
    PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
    BACKEND_DIR="$PROJECT_DIR/backend"
elif [ -f "$SCRIPT_DIR/app/main.py" ]; then
    # Docker: script is in /app, main.py is in /app/app/
    PROJECT_DIR="$SCRIPT_DIR"
    BACKEND_DIR="$SCRIPT_DIR"
elif [ -f "/app/app/main.py" ]; then
    PROJECT_DIR="/app"
    BACKEND_DIR="/app"
else
    err "Cannot find NTTH backend. Expected at $SCRIPT_DIR/../backend/"
    exit 1
fi
ok "Project directory: $PROJECT_DIR"
ok "Backend directory: $BACKEND_DIR"

# ── Step 3: Wireless adapter detection & monitor mode ──
WIFI_INTERFACE=""

if [ "$SKIP_WIFI" = false ]; then
    log "Scanning for wireless adapters..."

    # Known AR9271 USB ID
    if lsusb 2>/dev/null | grep -qi "0cf3:9271"; then
        ok "AR9271 (Atheros) detected via USB"

        # Check if already in monitor mode
        EXISTING_MON=$(iw dev 2>/dev/null | grep -A2 "type monitor" | grep "Interface" | awk '{print $2}' || true)
        
        if [ -n "$EXISTING_MON" ]; then
            ok "Already in monitor mode: $EXISTING_MON"
            WIFI_INTERFACE="$EXISTING_MON"
        else
            # Find the managed interface
            MANAGED_IFACE=$(airmon-ng 2>/dev/null | grep "ath9k_htc" | awk '{print $2}' || true)
            
            if [ -z "$MANAGED_IFACE" ]; then
                # Fallback: find any wireless interface with ath9k_htc
                MANAGED_IFACE=$(iw dev 2>/dev/null | grep "Interface" | awk '{print $2}' | head -1 || true)
            fi

            if [ -n "$MANAGED_IFACE" ]; then
                log "Found wireless interface: $MANAGED_IFACE"
                
                # Kill conflicting processes
                log "Killing conflicting processes..."
                airmon-ng check kill >/dev/null 2>&1 || true
                sleep 1
                ok "Conflicting processes killed"

                # Enable monitor mode
                log "Enabling monitor mode on $MANAGED_IFACE..."
                OUTPUT=$(airmon-ng start "$MANAGED_IFACE" 2>&1 || true)
                
                # Determine the monitor interface name
                # Try common names: wlan0mon, wlan1mon, etc.
                for TRY_IFACE in "${MANAGED_IFACE}mon" "wlan0mon" "wlan1mon"; do
                    if iw "$TRY_IFACE" info 2>/dev/null | grep -q "type monitor"; then
                        WIFI_INTERFACE="$TRY_IFACE"
                        break
                    fi
                done

                # If named differently, check original interface
                if [ -z "$WIFI_INTERFACE" ] && iw "$MANAGED_IFACE" info 2>/dev/null | grep -q "type monitor"; then
                    WIFI_INTERFACE="$MANAGED_IFACE"
                fi

                if [ -n "$WIFI_INTERFACE" ]; then
                    ok "Monitor mode enabled: $WIFI_INTERFACE"
                else
                    warn "Monitor mode failed. Backend will attempt auto-detection."
                fi
            else
                warn "No wireless interface found for AR9271 driver"
            fi
        fi

    elif lsusb 2>/dev/null | grep -qiE "148f:(5370|3070)|0bda:8187|0e8d:7612"; then
        ok "Compatible wireless adapter detected (non-AR9271)"
        warn "Auto-monitor will be attempted by the backend"
    else
        warn "No compatible wireless adapter found"
        warn "The system will run in wired-only mode"
    fi
else
    log "Wireless setup skipped (--no-wifi flag)"
fi

# ── Step 4: Set environment variables ──
if [ -n "$WIFI_INTERFACE" ]; then
    export WIFI_ENABLED=true
    export WIFI_INTERFACE="$WIFI_INTERFACE"
    ok "WIFI_ENABLED=true, WIFI_INTERFACE=$WIFI_INTERFACE"
fi

# ── Step 5: Check dependencies ──
log "Checking dependencies..."
if command -v python3 &>/dev/null; then
    PYTHON_VER=$(python3 --version 2>&1)
    ok "Python: $PYTHON_VER"
else
    err "Python3 not found. Install with: apt install python3"
    exit 1
fi

if python3 -c "import uvicorn" 2>/dev/null; then
    ok "uvicorn available"
else
    warn "uvicorn not found, installing..."
    pip install uvicorn[standard] >/dev/null 2>&1
fi

# ── Step 6: Start NTTH ──
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Starting NTTH backend on port $PORT..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Dashboard:  http://$(hostname -I | awk '{print $1}'):$PORT/"
echo "  API docs:   http://$(hostname -I | awk '{print $1}'):$PORT/docs"
echo "  Health:     http://localhost:$PORT/api/v1/system/health"
if [ -n "$WIFI_INTERFACE" ]; then
    echo "  Wireless:   Monitoring on $WIFI_INTERFACE (AR9271)"
fi
echo ""

cd "$BACKEND_DIR"

if [ "$DEV_MODE" = true ]; then
    exec python3 -m uvicorn app.main:app \
        --host 0.0.0.0 \
        --port "$PORT" \
        --reload \
        --log-level info
else
    exec python3 -m uvicorn app.main:app \
        --host 0.0.0.0 \
        --port "$PORT" \
        --log-level info \
        --workers 1
fi
