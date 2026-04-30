"""
Auto-Monitor — automatically detects the AR9271 (or any rtl8187/ath9k_htc)
USB WiFi adapter and puts it into monitor mode without manual intervention.

Called at backend startup so the system self-configures every time it boots.
"""
from __future__ import annotations

import subprocess
import re
from app.core.logger import get_logger

log = get_logger("auto_monitor")

# Known AR9271 / ath9k_htc USB identifiers
_AR9271_USB_IDS = {
    "0cf3:9271",  # Atheros AR9271
    "0cf3:7015",  # TP-Link TL-WN722N v1
    "0cf3:1006",  # Ubiquiti SR71-USB
    "148f:2770",  # Ralink (fallback)
    "0bda:8187",  # Realtek RTL8187
    "0bda:818a",  # Realtek RTL8187B
}

_monitor_status: dict = {
    "adapter_found": False,
    "base_interface": None,
    "monitor_interface": None,
    "mode": None,
    "error": None,
}


def _run(cmd: list[str], timeout: int = 8) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found"
    except Exception as exc:
        return -1, "", str(exc)


def _find_wifi_adapters() -> list[str]:
    """
    Enumerate wireless interfaces using 'iw dev' and match against
    known USB IDs via 'lsusb'. Returns list of interface names.
    """
    rc, out, _ = _run(["iw", "dev"])
    if rc != 0:
        return []

    # Parse interface names from `iw dev` output
    interfaces = re.findall(r"Interface\s+(\S+)", out)
    return interfaces


def _find_ar9271_interface() -> str | None:
    """
    Find the AR9271 adapter specifically by checking USB IDs then
    matching to a wireless interface via phy mapping.
    """
    # Check lsusb for known IDs
    rc, lsusb_out, _ = _run(["lsusb"])
    ar9271_present = False
    if rc == 0:
        for uid in _AR9271_USB_IDS:
            if uid.lower() in lsusb_out.lower():
                ar9271_present = True
                log.info("auto_monitor.ar9271_usb_detected", usb_id=uid)
                break

    # Even if lsusb didn't find it, check all wireless interfaces
    ifaces = _find_wifi_adapters()
    log.info("auto_monitor.interfaces_found", interfaces=ifaces)

    if not ifaces:
        if ar9271_present:
            log.warning("auto_monitor.usb_found_but_no_iface",
                        hint="Adapter USB detected but no wireless interface — try replugging")
        return None

    # Prefer any interface that's already in monitor mode
    for iface in ifaces:
        rc2, mode_out, _ = _run(["iw", "dev", iface, "info"])
        if rc2 == 0 and "type monitor" in mode_out:
            log.info("auto_monitor.already_monitor", interface=iface)
            return iface

    # Prefer USB WiFi adapters (wlx prefix = USB MAC-derived name, not built-in)
    # Built-in NICs are typically wlp* (PCI/PCIe)
    usb_ifaces = [i for i in ifaces if i.startswith("wlx")]
    if usb_ifaces:
        log.info("auto_monitor.usb_adapter_selected", interface=usb_ifaces[0],
                 reason="wlx prefix indicates USB adapter (AR9271)")
        return usb_ifaces[0]

    # Fall back to any non-loopback wireless interface
    for iface in ifaces:
        if not iface.startswith("lo"):
            return iface

    return None



def _set_monitor_mode(iface: str) -> str | None:
    """
    Put the interface into monitor mode.
    Tries airmon-ng first, falls back to correct iw dev commands.
    Returns the monitor interface name, or None on failure.
    """
    # Check if already in monitor mode
    rc, out, _ = _run(["iw", "dev", iface, "info"])
    if rc == 0 and "type monitor" in out:
        log.info("auto_monitor.already_in_monitor_mode", interface=iface)
        return iface

    # Kill interfering processes first (rfkill, wpa_supplicant, NetworkManager)
    _run(["airmon-ng", "check", "kill"], timeout=10)

    # Try airmon-ng start
    rc, out, err = _run(["airmon-ng", "start", iface], timeout=20)
    if rc == 0:
        # airmon-ng may rename to <iface>mon or keep same name
        for candidate in [f"{iface}mon", iface]:
            rc2, info_out, _ = _run(["iw", "dev", candidate, "info"])
            if rc2 == 0 and "type monitor" in info_out:
                log.info("auto_monitor.airmon_success", monitor_interface=candidate)
                return candidate

    # Fallback: correct iw commands — `iw dev <iface> set type monitor`
    log.info("auto_monitor.trying_iw_fallback", interface=iface)
    _run(["ip", "link", "set", iface, "down"])
    rc4, out4, err4 = _run(["iw", "dev", iface, "set", "type", "monitor"])
    _run(["ip", "link", "set", iface, "up"])

    if rc4 == 0:
        # Verify
        rc5, info5, _ = _run(["iw", "dev", iface, "info"])
        if rc5 == 0 and "type monitor" in info5:
            log.info("auto_monitor.iw_monitor_success", interface=iface)
            return iface

    log.warning("auto_monitor.monitor_mode_failed", interface=iface,
                error=err4 or "iw set type monitor returned non-zero")
    return None



def setup_monitor_interface() -> str | None:
    """
    Full auto-setup flow:
    1. Find the AR9271 / any WiFi adapter
    2. Put it in monitor mode
    3. Update the global status dict
    4. Return the monitor interface name (or None if not available)
    """
    global _monitor_status

    base_iface = _find_ar9271_interface()
    if not base_iface:
        _monitor_status = {
            "adapter_found": False,
            "base_interface": None,
            "monitor_interface": None,
            "mode": None,
            "error": "No WiFi adapter found",
        }
        log.warning("auto_monitor.no_adapter_found",
                    hint="Plug in the AR9271 adapter and restart the backend")
        return None

    _monitor_status["adapter_found"] = True
    _monitor_status["base_interface"] = base_iface

    mon_iface = _set_monitor_mode(base_iface)
    if not mon_iface:
        _monitor_status["monitor_interface"] = None
        _monitor_status["mode"] = "managed"
        _monitor_status["error"] = f"Could not enable monitor mode on {base_iface}"
        return None

    _monitor_status["monitor_interface"] = mon_iface
    _monitor_status["mode"] = "monitor"
    _monitor_status["error"] = None
    log.info("auto_monitor.ready", interface=mon_iface)
    return mon_iface


def get_monitor_status() -> dict:
    """Return the current auto-monitor setup status."""
    return dict(_monitor_status)
