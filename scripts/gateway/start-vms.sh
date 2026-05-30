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

if [ ! -f "$VM_DIR/alpine-base.qcow2" ]; then
  echo "❌ Base image not found at $VM_DIR/alpine-base.qcow2"
  echo "   Follow the VM installation guide first."
  exit 1
fi

# ── Step 1: Create the bridge ────────────────────────────────────────────────
echo "🌉 Setting up bridge: $BRIDGE"

if ip link show "$BRIDGE" &>/dev/null; then
  echo "   ✅ Bridge $BRIDGE already exists"
else
  ip link add name "$BRIDGE" type bridge
  echo "   ✅ Bridge $BRIDGE created"
fi

# Assign the gateway IP to the bridge (move from wireless interface)
ip addr flush dev "$BRIDGE" 2>/dev/null || true
ip addr add "$GW_IP/24" dev "$BRIDGE" 2>/dev/null || true
ip link set "$BRIDGE" up
echo "   ✅ Bridge IP: $GW_IP/24"

# ── Step 2: Create TAP interfaces and add to bridge ─────────────────────────
echo "🔌 Creating TAP interfaces..."

for i in $(seq 0 $((VM_COUNT - 1))); do
  TAP="tap${i}"
  if ip link show "$TAP" &>/dev/null; then
    ip link set "$TAP" down 2>/dev/null || true
    ip link delete "$TAP" 2>/dev/null || true
  fi
  ip tuntap add dev "$TAP" mode tap
  ip link set "$TAP" up
  ip link set "$TAP" master "$BRIDGE"
done
echo "   ✅ Created tap0 through tap$((VM_COUNT - 1))"

# ── Step 3: Enable IP forwarding ────────────────────────────────────────────
echo 1 > /proc/sys/net/ipv4/ip_forward
echo "   ✅ IP forwarding enabled"

# ── Step 4: Launch all VMs ──────────────────────────────────────────────────
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
