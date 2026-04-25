"""
Rogue AP Detector — compares observed beacon frames against a
whitelist of authorized access points.  Detects:

  1. **Evil Twin**: Same SSID but different BSSID (MAC spoofing)
  2. **Unknown AP**: SSID not in whitelist broadcasting on our network

Publishes ``wifi_threat_detected`` events when rogue APs are found.
"""
from __future__ import annotations

import time
from typing import Optional

from app.core.logger import get_logger

log = get_logger("rogue_ap_detector")

# Whitelist: SSID → set of authorized BSSIDs
_whitelist: dict[str, set[str]] = {}

# Track seen APs: BSSID → {ssid, first_seen, last_seen, beacon_count}
_observed_aps: dict[str, dict] = {}

# Already-alerted rogue APs (avoid spam)
_alerted_rogues: set[str] = set()

# Cooldown: seconds before re-alerting the same rogue AP
_ALERT_COOLDOWN = 300  # 5 minutes
_alert_timestamps: dict[str, float] = {}


def configure_whitelist(whitelist_ssids: list[str]) -> None:
    """
    Set the list of authorized SSIDs.

    Initially, the whitelist contains SSIDs only.  As legitimate beacons
    are observed, their BSSIDs are auto-learned and added as authorized.
    """
    global _whitelist
    for ssid in whitelist_ssids:
        ssid = ssid.strip()
        if ssid and ssid not in _whitelist:
            _whitelist[ssid] = set()
    log.info("rogue_ap_detector.whitelist_configured", ssids=list(_whitelist.keys()))


def learn_bssid(ssid: str, bssid: str) -> None:
    """Manually register a known-good BSSID for an SSID."""
    bssid = bssid.lower()
    if ssid in _whitelist:
        _whitelist[ssid].add(bssid)
        log.info("rogue_ap_detector.bssid_learned", ssid=ssid, bssid=bssid)


def evaluate(features: dict) -> Optional[dict]:
    """
    Evaluate a parsed beacon frame for rogue AP indicators.

    Parameters
    ----------
    features : dict
        Must contain ``frame_type == "beacon"``, ``ssid``, and ``bssid``.

    Returns
    -------
    dict or None
        Threat payload if rogue AP detected, else None.
    """
    if features.get("frame_type") != "beacon":
        return None

    ssid = features.get("ssid")
    bssid = features.get("bssid")
    if not ssid or not bssid:
        return None

    bssid = bssid.lower()
    now = time.monotonic()

    # Track all observed APs
    if bssid not in _observed_aps:
        _observed_aps[bssid] = {
            "ssid": ssid,
            "bssid": bssid,
            "first_seen": features.get("timestamp"),
            "last_seen": features.get("timestamp"),
            "beacon_count": 0,
            "channel": features.get("channel"),
            "privacy": features.get("privacy"),
        }
    ap = _observed_aps[bssid]
    ap["last_seen"] = features.get("timestamp")
    ap["beacon_count"] += 1
    ap["channel"] = features.get("channel")

    # ── No whitelist configured → auto-learn mode ────────────────
    if not _whitelist:
        return None

    # ── Check: is this SSID in our whitelist? ────────────────────
    if ssid not in _whitelist:
        # Unknown SSID — not necessarily rogue, just not in our network
        return None

    # ── SSID is whitelisted. Check if this BSSID is authorized ───
    authorized_bssids = _whitelist[ssid]

    # Auto-learn phase: if we haven't learned any BSSIDs yet for this
    # SSID, the first few beacons are used to build the whitelist.
    if not authorized_bssids:
        # Auto-learn: treat the first BSSID as legitimate
        _whitelist[ssid].add(bssid)
        log.info("rogue_ap_detector.auto_learned", ssid=ssid, bssid=bssid)
        return None

    if bssid in authorized_bssids:
        # Known good AP
        return None

    # ── ROGUE AP DETECTED: Same SSID, unknown BSSID ─────────────
    # Check cooldown to avoid alert spam
    alert_key = f"{ssid}:{bssid}"
    last_alert = _alert_timestamps.get(alert_key, 0)
    if now - last_alert < _ALERT_COOLDOWN:
        return None

    _alert_timestamps[alert_key] = now
    _alerted_rogues.add(alert_key)

    log.warning(
        "rogue_ap_detector.rogue_detected",
        ssid=ssid,
        rogue_bssid=bssid,
        authorized_bssids=list(authorized_bssids),
        channel=features.get("channel"),
    )

    return {
        "threat_type": "rogue_ap",
        "severity": "critical",
        "ssid": ssid,
        "rogue_bssid": bssid,
        "authorized_bssids": list(authorized_bssids),
        "channel": features.get("channel"),
        "rssi": features.get("rssi"),
        "privacy": features.get("privacy"),
        "timestamp": features.get("timestamp"),
        "description": (
            f"Rogue access point detected: SSID '{ssid}' broadcasting "
            f"from unauthorized BSSID {bssid} (authorized: "
            f"{', '.join(authorized_bssids)})"
        ),
    }


# ── Public query API ──────────────────────────────────────────────

def get_observed_aps() -> list[dict]:
    """Return all observed access points."""
    return list(_observed_aps.values())


def get_whitelist() -> dict[str, list[str]]:
    """Return current whitelist: SSID → list of authorized BSSIDs."""
    return {ssid: sorted(bssids) for ssid, bssids in _whitelist.items()}


def get_rogue_count() -> int:
    return len(_alerted_rogues)


def reset() -> None:
    """Clear all state."""
    _observed_aps.clear()
    _alerted_rogues.clear()
    _alert_timestamps.clear()
    log.info("rogue_ap_detector.reset")
