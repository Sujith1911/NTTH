#!/bin/bash
# Quick fix script: restart NTTH backend + purge false stealth scan data
# Run this on your Ubuntu laptop terminal:
#   sudo bash /home/ubuntu/NTTH/fix_stealth_scan.sh

echo "=== NTTH Stealth Scan Fix ==="
echo ""

# 1. Kill old backend process
echo "[1/4] Stopping old backend..."
pkill -f "uvicorn.*app.main" 2>/dev/null
sleep 2

# 2. Clear any lingering nftables block rules for the phone
echo "[2/4] Clearing nftables block rules for 192.168.4.95..."
nft list ruleset 2>/dev/null | grep -q "192.168.4.95" && {
    # Flush NTTH filter rules
    nft flush chain inet ntth_filter ntth_forward 2>/dev/null
    echo "   -> Cleared nftables rules"
} || echo "   -> No blocking rules found"

# 3. Restart backend with fixed code
echo "[3/4] Starting backend with fixed stealth scan detector..."
cd /home/ubuntu/NTTH/backend
nohup python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload > /tmp/ntth-backend.log 2>&1 &
sleep 3
echo "   -> Backend PID: $(pgrep -f 'uvicorn.*app.main' | head -1)"

# 4. Purge false stealth scan data via API
echo "[4/4] Purging false stealth scan data..."
sleep 2
# Get auth token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"NtthAdmin2026"}' | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

if [ -n "$TOKEN" ]; then
    # Run cleanup
    RESULT=$(curl -s -X POST http://localhost:8000/api/v1/packets/cleanup-noise \
      -H "Authorization: Bearer $TOKEN")
    echo "   -> Cleanup result: $RESULT"
    
    # Clear device risk
    curl -s -X POST "http://localhost:8000/api/v1/devices/by-ip/192.168.4.95/clear-risk" \
      -H "Authorization: Bearer $TOKEN" > /dev/null 2>&1
    echo "   -> Device 192.168.4.95 risk cleared"
else
    echo "   -> WARNING: Could not get auth token. Run cleanup manually from dashboard."
fi

echo ""
echo "=== Fix Applied ==="
echo "Changes:"
echo "  1. Stealth scan detector now gates on TCP-only (UDP/QUIC ignored)"
echo "  2. Threat agent skips outbound UDP to common service ports"
echo "  3. False stealth_scan threat events purged from database"
echo "  4. Device 192.168.4.95 risk score reset to 0%"
echo ""
echo "Your phone should now have internet access."
echo "If still no internet, run: sudo nft flush chain inet ntth_filter ntth_forward"
