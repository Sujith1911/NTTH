"""
Auto Monitor Mode — automatically detects and configures the AR9271
(or any compatible wireless adapter) into monitor mode at startup.

Flow:
  1. Scan USB devices for known chipsets (AR9271, RT5370, MT7612U, etc.)
  2. Find the corresponding network interface
  3. Kill conflicting processes (NetworkManager, wpa_supplicant)
  4. Enable monitor mode via `airmon-ng` or manual `iw` commands
  5. Update settings.wifi_interface with the monitor interface name
  6. Return status to the caller (main.py lifespan)

This runs BEFORE the WiFi sniffer starts, so by the time
start_wifi_sniffer() is called, the interface is ready.
"""
from __future__ import annotations

import asyncio
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from app.core.logger import get_logger

log = get_logger("auto_monitor")

# Known USB IDs for wireless adapters supporting monitor mode
_KNOWN_ADAPTERS = {
    "0cf3:9271": {"name": "Atheros AR9271", "driver": "ath9k_htc"},
    "148f:5370": {"name": "Ralink RT5370", "driver": "rt2800usb"},
    "148f:3070": {"name": "Ralink RT3070", "driver": "rt2800usb"},
    "0bda:8187": {"name": "Realtek RTL8187", "driver": "rtl8187"},
    "0e8d:7612": {"name": "MediaTek MT7612U", "driver": "mt76x2u"},
    "2357:010c": {"name": "TP-Link TL-WN722N v2", "driver": "ath9k_htc"},
}

# Status tracking
_status = {
    "adapter_found": False,
    "adapter_name": None,
    "adapter_usb_id": None,
    "original_interface": None,
    "monitor_interface": None,
    "method_used": None,  # "airmon-ng" | "iw" | "ip_link"
    "setup_success": False,
    "error": None,
}


def get_monitor_status() -> dict:
    """Return current auto-monitor setup status."""
    return {**_status}


def _run_cmd(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)


def detect_adapter() -> Optional[dict]:
    """
    Detect a compatible wireless adapter via lsusb.
    Returns adapter info dict or None.
    """
    rc, stdout, _ = _run_cmd(["lsusb"])
    if rc != 0:
        return None

    for line in stdout.splitlines():
        for usb_id, info in _KNOWN_ADAPTERS.items():
            if usb_id in line:
                log.info(
                    "auto_monitor.adapter_detected",
                    usb_id=usb_id,
                    name=info["name"],
                    driver=info["driver"],
                )
                return {"usb_id": usb_id, **info, "lsusb_line": line}

    # Also check for any adapter already in monitor mode
    rc, stdout, _ = _run_cmd(["iw", "dev"])
    if rc == 0 and "monitor" in stdout.lower():
        # Already in monitor mode
        match = re.search(r"Interface\s+(\S+)", stdout)
        if match:
            iface = match.group(1)
            log.info("auto_monitor.already_monitor_mode", interface=iface)
            return {
                "usb_id": "unknown",
                "name": "Pre-configured adapter",
                "driver": "unknown",
                "interface": iface,
                "already_monitor": True,
            }

    return None


def _find_interface_for_driver(driver: str) -> Optional[str]:
    """Find the wireless interface for a given driver."""
    # Method 1: Check /sys/class/net/*/device/driver
    net_path = Path("/sys/class/net")
    if net_path.exists():
        for iface_dir in net_path.iterdir():
            driver_link = iface_dir / "device" / "driver"
            if driver_link.exists():
                try:
                    resolved = driver_link.resolve().name
                    if resolved == driver:
                        return iface_dir.name
                except Exception:
                    pass

    # Method 2: Use airmon-ng to list
    rc, stdout, _ = _run_cmd(["airmon-ng"])
    if rc == 0:
        for line in stdout.splitlines():
            if driver in line:
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]  # Interface name

    # Method 3: Use iw dev
    rc, stdout, _ = _run_cmd(["iw", "dev"])
    if rc == 0:
        interfaces = re.findall(r"Interface\s+(\S+)", stdout)
        # Return the first wireless interface that's not already in monitor
        for iface in interfaces:
            rc2, stdout2, _ = _run_cmd(["iw", iface, "info"])
            if rc2 == 0 and "type managed" in stdout2:
                return iface

    return None


def _find_any_wireless_interface() -> Optional[str]:
    """Fallback: find any wireless interface."""
    rc, stdout, _ = _run_cmd(["iw", "dev"])
    if rc == 0:
        interfaces = re.findall(r"Interface\s+(\S+)", stdout)
        if interfaces:
            return interfaces[0]

    # Check /sys/class/net for wireless
    net_path = Path("/sys/class/net")
    if net_path.exists():
        for iface_dir in net_path.iterdir():
            wireless_dir = iface_dir / "wireless"
            if wireless_dir.exists():
                return iface_dir.name

    return None


def _kill_conflicting_processes() -> bool:
    """Kill processes that interfere with monitor mode."""
    killed = False

    # Try airmon-ng check kill first (cleanest)
    rc, stdout, _ = _run_cmd(["airmon-ng", "check", "kill"])
    if rc == 0:
        log.info("auto_monitor.killed_conflicts_airmon", output=stdout[:200])
        return True

    # Manual fallback
    for process in ["NetworkManager", "wpa_supplicant", "dhclient", "avahi-daemon"]:
        rc, _, _ = _run_cmd(["pkill", "-f", process])
        if rc == 0:
            killed = True
            log.info("auto_monitor.killed_process", process=process)

    return killed


def enable_monitor_mode(interface: str) -> Optional[str]:
    """
    Enable monitor mode on the given interface.
    Returns the monitor interface name (e.g., wlan0mon) or None on failure.

    Tries multiple methods:
      1. airmon-ng start <iface>  (preferred, handles everything)
      2. iw <iface> set type monitor (manual method)
      3. ip link + iw (alternative manual)
    """
    # Method 1: airmon-ng
    rc, stdout, stderr = _run_cmd(["airmon-ng", "start", interface], timeout=15)
    if rc == 0:
        # Parse output for monitor interface name
        # Common patterns: "monitor mode vif enabled on wlan0mon"
        # or "monitor mode already enabled for wlan0mon"
        mon_match = re.search(
            r"(?:enabled|enabled for|using)\s+(?:for\s+)?(?:\[.*?\])?\s*(\S*mon\S*)",
            stdout + stderr, re.IGNORECASE,
        )
        if mon_match:
            mon_iface = mon_match.group(1)
            _status["method_used"] = "airmon-ng"
            log.info("auto_monitor.enabled_airmon", interface=mon_iface)
            return mon_iface

        # Check if interface was renamed (e.g., wlan0 → wlan0mon)
        possible_mon = interface.rstrip("0123456789") + "0mon"
        rc2, stdout2, _ = _run_cmd(["iw", possible_mon, "info"])
        if rc2 == 0 and "monitor" in stdout2.lower():
            _status["method_used"] = "airmon-ng"
            return possible_mon

        # Check if original interface was converted in-place
        rc2, stdout2, _ = _run_cmd(["iw", interface, "info"])
        if rc2 == 0 and "monitor" in stdout2.lower():
            _status["method_used"] = "airmon-ng"
            return interface

    # Method 2: Manual iw commands
    log.info("auto_monitor.trying_manual_iw", interface=interface)
    _run_cmd(["ip", "link", "set", interface, "down"])
    rc, _, stderr = _run_cmd(["iw", interface, "set", "type", "monitor"])
    if rc == 0:
        _run_cmd(["ip", "link", "set", interface, "up"])
        _status["method_used"] = "iw"
        log.info("auto_monitor.enabled_manual_iw", interface=interface)
        return interface

    # Method 3: Create a separate monitor VIF
    log.info("auto_monitor.trying_vif", interface=interface)
    mon_vif = f"{interface}mon"
    _run_cmd(["iw", interface, "interface", "add", mon_vif, "type", "monitor"])
    _run_cmd(["ip", "link", "set", mon_vif, "up"])
    rc, stdout, _ = _run_cmd(["iw", mon_vif, "info"])
    if rc == 0 and "monitor" in stdout.lower():
        _status["method_used"] = "vif"
        log.info("auto_monitor.enabled_vif", interface=mon_vif)
        return mon_vif

    return None


def _verify_monitor_mode(interface: str) -> bool:
    """Verify that the interface is actually in monitor mode."""
    rc, stdout, _ = _run_cmd(["iw", interface, "info"])
    if rc == 0 and "type monitor" in stdout:
        return True

    # Fallback: check iwconfig
    rc, stdout, _ = _run_cmd(["iwconfig", interface])
    if rc == 0 and "Mode:Monitor" in stdout:
        return True

    return False


async def auto_setup_monitor() -> dict:
    """
    Complete auto-setup: detect → configure → verify.

    Called from main.py lifespan BEFORE WiFi sniffer starts.
    Returns status dict.
    """
    log.info("auto_monitor.starting_setup")

    # Skip if not root (monitor mode requires root)
    if os.geteuid() != 0:
        _status["error"] = "Must run as root (sudo) for monitor mode"
        log.warning("auto_monitor.not_root")
        return _status

    # Step 1: Detect adapter
    adapter = detect_adapter()
    if not adapter:
        _status["error"] = "No compatible wireless adapter found"
        log.warning("auto_monitor.no_adapter")
        return _status

    _status["adapter_found"] = True
    _status["adapter_name"] = adapter["name"]
    _status["adapter_usb_id"] = adapter.get("usb_id", "unknown")

    # Already in monitor mode?
    if adapter.get("already_monitor"):
        iface = adapter["interface"]
        _status["monitor_interface"] = iface
        _status["setup_success"] = True
        _status["method_used"] = "pre-configured"
        log.info("auto_monitor.already_ready", interface=iface)
        return _status

    # Step 2: Find the wireless interface
    interface = _find_interface_for_driver(adapter["driver"])
    if not interface:
        interface = _find_any_wireless_interface()
    if not interface:
        _status["error"] = f"Cannot find interface for driver {adapter['driver']}"
        log.warning("auto_monitor.no_interface", driver=adapter["driver"])
        return _status

    _status["original_interface"] = interface
    log.info("auto_monitor.found_interface", interface=interface, driver=adapter["driver"])

    # Step 3: Kill conflicting processes
    _kill_conflicting_processes()
    await asyncio.sleep(1)  # Let processes terminate

    # Step 4: Enable monitor mode
    mon_iface = enable_monitor_mode(interface)
    if not mon_iface:
        _status["error"] = f"Failed to enable monitor mode on {interface}"
        log.error("auto_monitor.enable_failed", interface=interface)
        return _status

    # Step 5: Verify
    await asyncio.sleep(0.5)
    if _verify_monitor_mode(mon_iface):
        _status["monitor_interface"] = mon_iface
        _status["setup_success"] = True
        log.info(
            "auto_monitor.setup_complete",
            adapter=adapter["name"],
            interface=mon_iface,
            method=_status["method_used"],
        )
    else:
        _status["error"] = f"Monitor mode verification failed on {mon_iface}"
        log.error("auto_monitor.verify_failed", interface=mon_iface)

    return _status


async def auto_teardown_monitor() -> None:
    """Disable monitor mode and restore the interface (called on shutdown)."""
    mon_iface = _status.get("monitor_interface")
    orig_iface = _status.get("original_interface")
    method = _status.get("method_used")

    if not mon_iface:
        return

    log.info("auto_monitor.teardown", interface=mon_iface)

    if method == "airmon-ng":
        _run_cmd(["airmon-ng", "stop", mon_iface])
    elif method == "vif":
        _run_cmd(["iw", mon_iface, "del"])
    elif method == "iw" and orig_iface:
        _run_cmd(["ip", "link", "set", mon_iface, "down"])
        _run_cmd(["iw", mon_iface, "set", "type", "managed"])
        _run_cmd(["ip", "link", "set", mon_iface, "up"])

    # Restart NetworkManager if available
    _run_cmd(["systemctl", "start", "NetworkManager"])

    _status["setup_success"] = False
    _status["monitor_interface"] = None
    log.info("auto_monitor.teardown_complete")
