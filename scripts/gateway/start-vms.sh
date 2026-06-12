#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# NTTH VM Fleet Launcher
# Creates br-ntth bridge, TAP interfaces, and launches all 12 Alpine VMs.
# Usage: sudo bash start-vms.sh
# ──────────────────────────────────────────────────────────────────────────────
set -e

VM_DIR="$HOME/NTTH/vms"
# If running as root via sudo, use the real user's home
if [ -n "$SUDO_USER" ]; then
  VM_DIR="$(eval echo ~$SUDO_USER)/NTTH/vms"
fi

BRIDGE="br-ntth"
GW_IP="192.168.4.1"
GW_IFACE="wlx24ec99bfe292"
VM_COUNT=12
PIDS_FILE="/tmp/ntth-vm-pids"

# VM definitions: name, disk file, RAM (MB), MAC suffix
VM_NAMES=(
  "vm-atk-01" "vm-atk-02" "vm-atk-03" "vm-atk-04"
  "vm-tgt-01" "vm-tgt-02" "vm-tgt-03" "vm-tgt-04"
  "vm-usr-01" "vm-usr-02" "vm-usr-03" "vm-usr-04"
)
VM_RAM=(
  256 256 256 256
  256 256 256 256
  128 128 128 128
)

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║    NTTH VM Fleet — Starting 12 VMs  🖥️       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── Check prerequisites ──────────────────────────────────────────────────────
if ! command -v qemu-system-x86_64 &>/dev/null; then
  echo "❌ qemu-system-x86_64 not found. Run: sudo apt install qemu-system-x86"
  exit 1
fi
if ! command -v ebtables &>/dev/null; then
  echo "❌ ebtables not found. Run: sudo apt install ebtables"
  exit 1
fi

if [ ! -f "$VM_DIR/alpine-base.qcow2" ]; then
  echo "❌ Base image not found at $VM_DIR/alpine-base.qcow2"
  echo "   Follow the VM installation guide first."
  exit 1
fi

# ── Step 0: Refuse to start VMs if the real hotspot is already unhealthy ────
HOSTAPD_STATUS=$(systemctl is-active hostapd 2>/dev/null || true)
DNSMASQ_STATUS=$(systemctl is-active dnsmasq 2>/dev/null || true)
AP_MODE=$(iw dev "$GW_IFACE" info 2>/dev/null | awk '/type/ {print $2}')
if [ "$HOSTAPD_STATUS" != "active" ] || [ "$DNSMASQ_STATUS" != "active" ] || [ "$AP_MODE" != "AP" ]; then
  echo "❌ Gateway hotspot is not healthy; refusing to start VMs."
  echo "   hostapd:  ${HOSTAPD_STATUS:-unknown}"
  echo "   dnsmasq:  ${DNSMASQ_STATUS:-unknown}"
  echo "   $GW_IFACE mode: ${AP_MODE:-unknown}"
  echo ""
  echo "   Fix first: sudo bash start.sh --gateway"
  echo "   Why: VMs share br-ntth with real devices, so starting them while"
  echo "        the AP is down/managed makes real devices appear disconnected."
  exit 1
fi

# ── Step 1: Verify the live gateway bridge ──────────────────────────────────
echo "🌉 Verifying gateway bridge: $BRIDGE"

if ip link show "$BRIDGE" &>/dev/null; then
  echo "   ✅ Bridge $BRIDGE already exists"
else
  ip link add name "$BRIDGE" type bridge
  echo "   ⚠️  Bridge $BRIDGE was missing and has been created"
fi

# Never flush or replace the bridge address here. Real hotspot devices use it
# as their gateway, and removing it during VM startup disconnects live clients.
if ! ip -4 addr show dev "$BRIDGE" | grep -q "inet ${GW_IP}/24"; then
  ip addr add "$GW_IP/24" dev "$BRIDGE"
fi
ip link set "$BRIDGE" up
echo "   ✅ Bridge IP preserved: $GW_IP/24"

# ── Step 2: Enable IP forwarding ────────────────────────────────────────────
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "   ✅ IP forwarding enabled"

# ── Step 3: Launch VMs and attach only the TAP ports they need ──────────────
echo ""
echo "🚀 Launching VMs..."
> "$PIDS_FILE"  # Clear PID file

LOG_DIR="/tmp/ntth-vm-logs"
mkdir -p "$LOG_DIR"

for i in $(seq 0 $((VM_COUNT - 1))); do
  NAME="${VM_NAMES[$i]}"
  DISK="$VM_DIR/${NAME}.qcow2"
  RAM="${VM_RAM[$i]}"
  TAP="tap${i}"

  # Generate unique MAC address: 52:54:00:NT:TH:XX
  MAC=$(printf "52:54:00:4e:54:%02x" $((i + 1)))

  if [ ! -f "$DISK" ]; then
    echo "   ⚠️  Skipping $NAME — disk not found: $DISK"
    continue
  fi

  if ip link show "$TAP" &>/dev/null; then
    ip link set "$TAP" down 2>/dev/null || true
    ip link delete "$TAP" 2>/dev/null || true
  fi
  ip tuntap add dev "$TAP" mode tap
  ip link set "$TAP" master "$BRIDGE"
  ip link set "$TAP" up

  # VMs may generate arbitrary attack traffic, but they must never replace
  # dnsmasq or impersonate the gateway used by real hotspot clients.
  while ebtables -D FORWARD -i "$TAP" -p IPv4 --ip-proto udp --ip-sport 67 -j DROP 2>/dev/null; do :; done
  while ebtables -D FORWARD -i "$TAP" -p ARP --arp-ip-src "$GW_IP" -j DROP 2>/dev/null; do :; done
  ebtables -A FORWARD -i "$TAP" -p IPv4 --ip-proto udp --ip-sport 67 -j DROP
  ebtables -A FORWARD -i "$TAP" -p ARP --arp-ip-src "$GW_IP" -j DROP

  nohup qemu-system-x86_64 \
    -enable-kvm \
    -m "$RAM" \
    -hda "$DISK" \
    -net nic,macaddr="$MAC",model=virtio \
    -net tap,ifname="$TAP",script=no,downscript=no \
    -nographic \
    -name "$NAME" \
    > "$LOG_DIR/${NAME}.log" 2>&1 &

  PID=$!
  echo "$NAME $PID" >> "$PIDS_FILE"
  echo "   ✅ $NAME  |  RAM: ${RAM}MB  |  MAC: $MAC  |  TAP: $TAP  |  PID: $PID"

  # Small delay to avoid overwhelming KVM
  sleep 0.5
done

echo ""
echo "═══════════════════════════════════════════════"
echo "✅ All VMs launched!"
echo ""
echo "   Bridge:     $BRIDGE ($GW_IP)"
echo "   VMs:        $(wc -l < "$PIDS_FILE") running"
echo "   PID file:   $PIDS_FILE"
echo ""
echo "   To stop all VMs:  sudo bash stop-vms.sh"
echo "   To SSH into a VM: ssh root@<vm-ip>  (password: ntth)"
echo "   To see VM IPs:    cat /var/lib/misc/dnsmasq.leases"
echo "═══════════════════════════════════════════════"
