"""
WiFi 802.11 feature extractor — parses raw Dot11 frames captured in
monitor mode into structured feature dicts for downstream processing.

Extracts three frame types relevant to wireless threat detection:
  1. Probe Requests  — device presence tracking
  2. Deauth frames   — deauthentication attack detection
  3. Beacon frames   — rogue AP / evil twin detection
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional


def extract_wifi_features(pkt) -> Optional[dict]:
    """
    Parse a raw Scapy packet captured in monitor mode.

    Returns a dict with ``frame_type`` set to one of:
    ``probe_request``, ``deauth``, ``beacon``, or ``None`` if the
    frame is not relevant to our detection pipeline.
    """
    try:
        from scapy.layers.dot11 import (  # type: ignore
            Dot11,
            Dot11Beacon,
            Dot11Deauth,
            Dot11Elt,
            Dot11ProbeReq,
            RadioTap,
        )
    except ImportError:
        return None

    if not pkt.haslayer(Dot11):
        return None

    dot11 = pkt[Dot11]
    now = datetime.utcnow().isoformat()

    # ── Extract RSSI from RadioTap header ────────────────────────
    rssi: Optional[int] = None
    if pkt.haslayer(RadioTap):
        rssi = getattr(pkt[RadioTap], "dBm_AntSignal", None)

    # ── Extract channel from RadioTap ────────────────────────────
    channel: Optional[int] = None
    if pkt.haslayer(RadioTap):
        freq = getattr(pkt[RadioTap], "ChannelFrequency", None)
        if freq and 2400 <= freq <= 2500:
            channel = (freq - 2407) // 5

    # ── 1. Probe Request ─────────────────────────────────────────
    if pkt.haslayer(Dot11ProbeReq):
        ssid = _extract_ssid(pkt)
        return {
            "frame_type": "probe_request",
            "src_mac": dot11.addr2,  # Transmitter MAC
            "dst_mac": dot11.addr1,  # Usually broadcast
            "ssid": ssid,
            "rssi": rssi,
            "channel": channel,
            "timestamp": now,
        }

    # ── 2. Deauthentication ──────────────────────────────────────
    if pkt.haslayer(Dot11Deauth):
        reason = pkt[Dot11Deauth].reason
        return {
            "frame_type": "deauth",
            "src_mac": dot11.addr2,     # Who sent the deauth
            "dst_mac": dot11.addr1,     # Target client (or broadcast)
            "bssid": dot11.addr3,       # AP being targeted
            "reason_code": reason,
            "rssi": rssi,
            "channel": channel,
            "timestamp": now,
        }

    # ── 3. Beacon ────────────────────────────────────────────────
    if pkt.haslayer(Dot11Beacon):
        ssid = _extract_ssid(pkt)
        bssid = dot11.addr3 or dot11.addr2
        # Extract capabilities
        cap = pkt[Dot11Beacon].cap
        privacy = bool(cap & 0x0010)  # WPA/WPA2 flag
        return {
            "frame_type": "beacon",
            "bssid": bssid,
            "ssid": ssid,
            "rssi": rssi,
            "channel": channel,
            "privacy": privacy,
            "timestamp": now,
        }

    return None


def _extract_ssid(pkt) -> Optional[str]:
    """Pull the SSID string from the first Dot11Elt with ID 0."""
    try:
        from scapy.layers.dot11 import Dot11Elt  # type: ignore
    except ImportError:
        return None

    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:  # SSID parameter set
            try:
                ssid = elt.info.decode("utf-8", errors="replace").strip()
                return ssid if ssid else None  # Empty SSID = broadcast probe
            except Exception:
                return None
        elt = elt.payload.getlayer(Dot11Elt)
    return None
