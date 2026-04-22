"""
Persistent Attacker Tracker — tracks attackers by MAC address across
sessions, IP changes, and reconnections.

When an attacker is detected:
  1. Their MAC is captured (from ARP table or WiFi probe)
  2. A fingerprint is built: MAC + vendor + hostname + probe SSIDs
  3. Stored in DB — persists across system reboots

When ANY device connects to the network later:
  - Its MAC is checked against the attacker registry
  - If matched → auto-flagged with full attack history
  - Even if IP changed (DHCP reassignment)
  - Even if days/weeks later

Also uses AR9271 WiFi probe tracking:
  - Detects attacker's device probe requests BEFORE they fully connect
  - Tracks RSSI (signal strength) for physical proximity estimation
"""
from __future__ import annotations

import json as _json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.core.logger import get_logger

log = get_logger("persistent_tracker")

# Persistence file path (survives restarts)
_PERSIST_FILE = os.environ.get(
    "TRACKER_PERSIST_FILE",
    str(Path(__file__).resolve().parent.parent.parent / "data" / "known_attackers.json"),
)

# In-memory index: MAC → attacker profile (synced to disk on each update)
_known_attackers: dict[str, dict] = {}


def _save_to_disk() -> None:
    """Persist attacker registry to JSON file."""
    try:
        path = Path(_PERSIST_FILE)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            _json.dump(_known_attackers, f, indent=2, default=str)
    except Exception as exc:
        log.debug("persistent_tracker.save_failed", error=str(exc))


def _load_from_disk() -> None:
    """Load attacker registry from JSON file on startup."""
    global _known_attackers
    try:
        path = Path(_PERSIST_FILE)
        if path.exists():
            with open(path) as f:
                _known_attackers = _json.load(f)
            log.info(
                "persistent_tracker.loaded",
                count=len(_known_attackers),
                path=str(path),
            )
    except Exception as exc:
        log.warning("persistent_tracker.load_failed", error=str(exc))


# Load persisted data at import time
_load_from_disk()


def flag_attacker(
    src_ip: str,
    mac: Optional[str] = None,
    threat_type: str = "unknown",
    risk_score: float = 0.0,
    hostname: Optional[str] = None,
    vendor: Optional[str] = None,
    wifi_ssids: Optional[list[str]] = None,
) -> Optional[dict]:
    """
    Register or update an attacker in the persistent tracker.

    Called by the enforcement agent when an IP is blocked or honeypotted.
    If we know the MAC, we create a persistent fingerprint that survives
    IP changes and reconnections.
    """
    if not mac:
        mac = _resolve_mac(src_ip)
    if not mac:
        # No MAC available — store by IP only (less persistent)
        return None

    mac = mac.lower()
    now = datetime.utcnow()

    if mac in _known_attackers:
        entry = _known_attackers[mac]
        entry["last_seen"] = now.isoformat()
        entry["attack_count"] += 1
        if src_ip not in entry["known_ips"]:
            entry["known_ips"].append(src_ip)
        if threat_type not in entry["threat_types"]:
            entry["threat_types"].append(threat_type)
        entry["last_risk_score"] = max(entry["last_risk_score"], risk_score)
        entry["last_ip"] = src_ip
        if wifi_ssids:
            entry["wifi_ssids"] = list(set(entry.get("wifi_ssids", []) + wifi_ssids))
        log.warning(
            "persistent_tracker.returning_attacker",
            mac=mac, ip=src_ip, attack_count=entry["attack_count"],
            known_ips=entry["known_ips"],
        )
    else:
        entry = {
            "mac": mac,
            "first_seen": now.isoformat(),
            "last_seen": now.isoformat(),
            "last_ip": src_ip,
            "known_ips": [src_ip],
            "threat_types": [threat_type],
            "attack_count": 1,
            "last_risk_score": risk_score,
            "hostname": hostname,
            "vendor": vendor or _lookup_vendor(mac),
            "wifi_ssids": wifi_ssids or [],
            "is_mac_randomized": _is_randomized_mac(mac),
            "status": "flagged",  # flagged | blocked | watched
        }
        _known_attackers[mac] = entry
        log.warning(
            "persistent_tracker.new_attacker_flagged",
            mac=mac, ip=src_ip, vendor=entry["vendor"],
        )

    # Persist to disk after every update
    _save_to_disk()
    return entry


def check_device(mac: str, current_ip: Optional[str] = None) -> Optional[dict]:
    """
    Check if a MAC address belongs to a known attacker.

    Called during:
      - Network scan (ARP discovery)
      - WiFi probe tracking (AR9271)
      - New device registration

    Returns the attacker profile if found, None otherwise.
    """
    mac = mac.lower()
    entry = _known_attackers.get(mac)
    if entry:
        # Update with new IP if changed
        if current_ip and current_ip not in entry["known_ips"]:
            entry["known_ips"].append(current_ip)
            entry["last_ip"] = current_ip
            entry["last_seen"] = datetime.utcnow().isoformat()
            log.warning(
                "persistent_tracker.attacker_reconnected",
                mac=mac, new_ip=current_ip,
                previous_ips=entry["known_ips"][:-1],
                days_since_first=_days_since(entry["first_seen"]),
            )
        return entry
    return None


def check_wifi_probe(mac: str, ssids: list[str] = None) -> Optional[dict]:
    """
    Check WiFi probe requests against known attacker MACs.

    This catches attackers BEFORE they fully connect — their phone/laptop
    sends probe requests for saved networks even while just passing by.
    """
    mac = mac.lower()
    entry = _known_attackers.get(mac)
    if entry:
        entry["last_seen"] = datetime.utcnow().isoformat()
        if ssids:
            entry["wifi_ssids"] = list(set(entry.get("wifi_ssids", []) + ssids))
        log.warning(
            "persistent_tracker.attacker_probe_detected",
            mac=mac,
            ssids=ssids,
            status="NOT_CONNECTED_YET",
            hint="Known attacker device detected nearby via WiFi probe",
        )
        return entry
    return None


def _resolve_mac(ip: str) -> Optional[str]:
    """Look up MAC address from ARP table for a given IP."""
    import subprocess
    try:
        if sys.platform == "linux":
            result = subprocess.run(
                ["ip", "neigh", "show", ip],
                capture_output=True, text=True, timeout=3,
            )
            if result.stdout:
                parts = result.stdout.strip().split()
                for i, p in enumerate(parts):
                    if p == "lladdr" and i + 1 < len(parts):
                        return parts[i + 1].lower()
    except Exception:
        pass
    return None


def _lookup_vendor(mac: str) -> Optional[str]:
    """Quick OUI vendor lookup."""
    try:
        from app.monitor.network_scanner import _vendor_from_mac
        return _vendor_from_mac(mac)
    except Exception:
        return None


def _is_randomized_mac(mac: str) -> bool:
    """Check if MAC is locally administered (randomized)."""
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def _days_since(iso_timestamp: str) -> float:
    """Calculate days since a given ISO timestamp."""
    try:
        then = datetime.fromisoformat(iso_timestamp)
        return round((datetime.utcnow() - then).total_seconds() / 86400, 1)
    except Exception:
        return 0.0


# ── Public query API ──────────────────────────────────────────────

def get_all_attackers() -> list[dict]:
    """Return all known attacker profiles."""
    return list(_known_attackers.values())


def get_attacker_by_mac(mac: str) -> Optional[dict]:
    return _known_attackers.get(mac.lower())


def get_attacker_by_ip(ip: str) -> Optional[dict]:
    """Find attacker profile by any of their known IPs."""
    for entry in _known_attackers.values():
        if ip in entry["known_ips"]:
            return entry
    return None


def get_attacker_count() -> int:
    return len(_known_attackers)


def clear_attacker(mac: str) -> bool:
    """Remove an attacker from the tracker (admin action)."""
    mac = mac.lower()
    if mac in _known_attackers:
        del _known_attackers[mac]
        _save_to_disk()
        log.info("persistent_tracker.cleared", mac=mac)
        return True
    return False


import sys

# Alias used by API routes
remove_attacker = clear_attacker
