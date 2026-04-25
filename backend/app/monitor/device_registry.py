"""
In-memory device registry with periodic DB flush.
Tracks packets, ports, bytes, and SYN counts per source IP.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from app.core.logger import get_logger

log = get_logger("device_registry")

# Per-IP in-memory state
_registry: dict[str, dict] = defaultdict(lambda: {
    "first_seen": None,
    "last_seen": None,
    "packet_count": 0,
    "byte_count": 0,
    "syn_count": 0,
    "ports_seen": set(),
})


def update(features: dict) -> dict:
    """Update registry for the source IP in `features`. Returns current state."""
    ip = features.get("src_ip")
    if not ip:
        return {}

    entry = _registry[ip]
    now = datetime.utcnow()

    if entry["first_seen"] is None:
        entry["first_seen"] = now
        log.debug("device_registry.new_device", ip=ip)

    entry["last_seen"] = now
    entry["packet_count"] += 1
    entry["byte_count"] += features.get("pkt_len", 0)

    if features.get("is_syn"):
        entry["syn_count"] += 1

    port = features.get("dst_port")
    if port:
        entry["ports_seen"].add(port)

    return {
        "ip": ip,
        "first_seen": entry["first_seen"],
        "last_seen": entry["last_seen"],
        "packet_count": entry["packet_count"],
        "byte_count": entry["byte_count"],
        "syn_count": entry["syn_count"],
        "unique_ports": len(entry["ports_seen"]),
    }


def get_state(ip: str) -> dict:
    """Return current registry state for an IP (empty dict if unknown)."""
    raw = _registry.get(ip)
    if not raw:
        return {}
    return {
        "ip": ip,
        "first_seen": raw["first_seen"],
        "last_seen": raw["last_seen"],
        "packet_count": raw["packet_count"],
        "byte_count": raw["byte_count"],
        "syn_count": raw["syn_count"],
        "unique_ports": len(raw["ports_seen"]),
        "ports_seen": list(raw["ports_seen"]),
    }


def get_all_ips() -> list[str]:
    return list(_registry.keys())
