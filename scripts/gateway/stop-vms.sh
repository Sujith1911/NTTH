#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# NTTH VM Fleet — Stop All VMs
# Usage: sudo bash stop-vms.sh
# ──────────────────────────────────────────────────────────────────────────────

PIDS_FILE="/tmp/ntth-vm-pids"
BRIDGE="br-ntth"
VM_COUNT=12

echo ""
echo "🛑 Stopping NTTH VM Fleet..."
echo ""

# ── Step 1: Kill all VM processes ────────────────────────────────────────────
if [ -f "$PIDS_FILE" ]; then
  while read -r NAME PID; do
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
      kill "$PID" 2>/dev/null || true
      echo "   ✅ Stopped $NAME (PID: $PID)"
    else
      echo "   ⚠️  $NAME already stopped"
    fi
  done < "$PIDS_FILE"
  rm -f "$PIDS_FILE"
else
  echo "   ⚠️  No PID file found, killing all QEMU processes..."
  pkill -f "qemu-system-x86_64.*ntth" 2>/dev/null || true
fi

# Also clean up any stray PID files
rm -f /tmp/ntth-vm-*.pid 2>/dev/null

# ── Step 2: Remove TAP interfaces ───────────────────────────────────────────
echo ""
echo "🔌 Cleaning up TAP interfaces..."
for i in $(seq 0 $((VM_COUNT - 1))); do
  TAP="tap${i}"
  while ebtables -D FORWARD -i "$TAP" -p IPv4 --ip-proto udp --ip-sport 67 -j DROP 2>/dev/null; do :; done
  while ebtables -D FORWARD -i "$TAP" -p ARP --arp-ip-src "192.168.4.1" -j DROP 2>/dev/null; do :; done
  if ip link show "$TAP" &>/dev/null; then
    ip link set "$TAP" down 2>/dev/null || true
    ip link delete "$TAP" 2>/dev/null || true
  fi
done
echo "   ✅ TAP interfaces removed"

# ── Step 3: Remove bridge (optional — comment out if you want to keep it) ──
# echo "🌉 Removing bridge..."
# if ip link show "$BRIDGE" &>/dev/null; then
#   ip link set "$BRIDGE" down
#   ip link delete "$BRIDGE"
#   echo "   ✅ Bridge $BRIDGE removed"
# fi

echo ""
echo "✅ All VMs stopped and cleaned up."
echo ""
