"""
Probe Tracker — in-memory registry of WiFi devices discovered
through 802.11 Probe Request frames captured by the AR9271.

Tracks per-MAC:
  - SSIDs the device has probed for (preferred network list)
  - RSSI history (signal strength over time)
  - First / last seen timestamps
  - Probe request count
  - Channel last seen on

Publishes ``wifi_device_update`` events for the reporting pipeline.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Optional

from app.core.event_bus import publish
from app.core.logger import get_logger

log = get_logger("probe_tracker")

# MAC → device state
_registry: dict[str, dict] = {}

# Maximum RSSI history entries per device
_MAX_RSSI_HISTORY = 50


def update(features: dict) -> Optional[dict]:
    """
    Update the probe tracker with a parsed probe request.

    Parameters
    ----------
    features : dict
        Must contain ``frame_type == "probe_request"`` and ``src_mac``.

    Returns
    -------
    dict or None
        Current device state, or None if features are invalid.
    """
    if features.get("frame_type") != "probe_request":
        return None

    mac = features.get("src_mac")
    if not mac:
        return None

    mac = mac.lower()
    now = datetime.utcnow()
    ssid = features.get("ssid")
    rssi = features.get("rssi")
    channel = features.get("channel")

    if mac not in _registry:
        _registry[mac] = {
            "mac": mac,
            "first_seen": now,
            "last_seen": now,
            "probe_count": 0,
            "ssids": set(),
            "rssi_history": [],
            "last_rssi": None,
            "last_channel": None,
            "is_randomized": _is_randomized_mac(mac),
        }
        log.info("probe_tracker.new_device", mac=mac, ssid=ssid)

    entry = _registry[mac]
    entry["last_seen"] = now
    entry["probe_count"] += 1

    if ssid:
        entry["ssids"].add(ssid)

    if rssi is not None:
        entry["rssi_history"].append({"rssi": rssi, "ts": now.isoformat()})
        if len(entry["rssi_history"]) > _MAX_RSSI_HISTORY:
            entry["rssi_history"] = entry["rssi_history"][-_MAX_RSSI_HISTORY:]
        entry["last_rssi"] = rssi

    if channel is not None:
        entry["last_channel"] = channel

    return _serialize(entry)


def _is_randomized_mac(mac: str) -> bool:
    """
    Detect locally-administered (randomized) MAC addresses.

    The second hex digit's least significant bit being 1 indicates
    a locally administered address (common in iOS/Android MAC randomization).
    """
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def _serialize(entry: dict) -> dict:
    """Convert internal state to a JSON-safe dict."""
    return {
        "mac": entry["mac"],
        "first_seen": entry["first_seen"].isoformat() if entry["first_seen"] else None,
        "last_seen": entry["last_seen"].isoformat() if entry["last_seen"] else None,
        "probe_count": entry["probe_count"],
        "ssids": sorted(entry["ssids"]),
        "last_rssi": entry["last_rssi"],
        "last_channel": entry["last_channel"],
        "is_randomized": entry["is_randomized"],
        "rssi_avg": _avg_rssi(entry["rssi_history"]),
    }


def _avg_rssi(history: list) -> Optional[float]:
    """Calculate average RSSI from recent history."""
    if not history:
        return None
    values = [h["rssi"] for h in history[-10:] if h.get("rssi") is not None]
    return round(sum(values) / len(values), 1) if values else None


# ── Public query API ──────────────────────────────────────────────

def get_all_devices() -> list[dict]:
    """Return serialized list of all tracked WiFi devices."""
    return [_serialize(entry) for entry in _registry.values()]


def get_device(mac: str) -> Optional[dict]:
    """Return state for a specific MAC, or None."""
    entry = _registry.get(mac.lower())
    return _serialize(entry) if entry else None


def get_device_count() -> int:
    return len(_registry)


def get_unique_ssids() -> list[str]:
    """Return all unique SSIDs seen across all devices."""
    all_ssids: set[str] = set()
    for entry in _registry.values():
        all_ssids.update(entry["ssids"])
    return sorted(all_ssids)


def reset() -> None:
    """Clear all tracked devices."""
    _registry.clear()
    log.info("probe_tracker.reset")
