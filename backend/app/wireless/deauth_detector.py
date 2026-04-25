"""
Deauthentication Attack Detector — monitors for high-rate deauth
frames targeting the same BSSID, which indicates a deauthentication
flood attack (commonly a precursor to evil twin / WPA handshake capture).

Uses a sliding-window approach identical to the wired IDS rule engine.
Publishes ``wifi_threat_detected`` events when thresholds are breached.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Optional

from app.core.logger import get_logger

log = get_logger("deauth_detector")

# Sliding windows: BSSID → deque of timestamps
_deauth_windows: dict[str, deque[float]] = defaultdict(deque)

# Configurable thresholds (overridden by config.py settings)
_DEAUTH_THRESHOLD = 10       # frames per window to trigger
_DEAUTH_WINDOW_SECONDS = 1.0  # sliding window duration


def configure(threshold: int = 10, window_seconds: float = 1.0) -> None:
    """Update detection thresholds from application config."""
    global _DEAUTH_THRESHOLD, _DEAUTH_WINDOW_SECONDS
    _DEAUTH_THRESHOLD = threshold
    _DEAUTH_WINDOW_SECONDS = window_seconds
    log.info(
        "deauth_detector.configured",
        threshold=threshold,
        window_seconds=window_seconds,
    )


def evaluate(features: dict) -> Optional[dict]:
    """
    Evaluate a parsed deauth frame for attack indicators.

    Parameters
    ----------
    features : dict
        Must contain ``frame_type == "deauth"`` and ``bssid``.

    Returns
    -------
    dict or None
        Threat payload if attack detected, else None.
    """
    if features.get("frame_type") != "deauth":
        return None

    bssid = features.get("bssid")
    if not bssid:
        return None

    bssid = bssid.lower()
    now = time.monotonic()
    window = _deauth_windows[bssid]

    # Add current frame
    window.append(now)

    # Prune old entries
    cutoff = now - _DEAUTH_WINDOW_SECONDS
    while window and window[0] < cutoff:
        window.popleft()

    rate = len(window)

    if rate >= _DEAUTH_THRESHOLD:
        src_mac = features.get("src_mac", "unknown")
        dst_mac = features.get("dst_mac", "unknown")
        reason_code = features.get("reason_code")

        log.warning(
            "deauth_detector.attack_detected",
            bssid=bssid,
            src_mac=src_mac,
            rate=rate,
            threshold=_DEAUTH_THRESHOLD,
        )

        return {
            "threat_type": "deauth_attack",
            "severity": "high",
            "bssid": bssid,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "reason_code": reason_code,
            "deauth_rate": rate,
            "threshold": _DEAUTH_THRESHOLD,
            "channel": features.get("channel"),
            "rssi": features.get("rssi"),
            "timestamp": features.get("timestamp"),
            "description": (
                f"Deauthentication flood detected: {rate} deauth frames/sec "
                f"targeting BSSID {bssid} from {src_mac}"
            ),
        }

    return None


def get_stats() -> dict:
    """Return current deauth monitoring statistics."""
    now = time.monotonic()
    active_bssids = {}
    for bssid, window in _deauth_windows.items():
        # Prune stale
        cutoff = now - _DEAUTH_WINDOW_SECONDS
        while window and window[0] < cutoff:
            window.popleft()
        if window:
            active_bssids[bssid] = len(window)

    return {
        "monitored_bssids": len(_deauth_windows),
        "active_bssids": active_bssids,
        "threshold": _DEAUTH_THRESHOLD,
        "window_seconds": _DEAUTH_WINDOW_SECONDS,
    }


def reset() -> None:
    """Clear all sliding window state."""
    _deauth_windows.clear()
    log.info("deauth_detector.reset")
