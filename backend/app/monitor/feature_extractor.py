"""
Extract security-relevant features from a raw Scapy packet.
Returns a dict suitable for IDS scoring and device registry.
"""
from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Optional

from app.config import get_settings

settings = get_settings()
_IGNORED_NETWORKS = tuple(ip_network(cidr) for cidr in settings.ignored_monitor_cidrs)


def _should_ignore(ip: str) -> bool:
    try:
        parsed = ip_address(ip)
    except ValueError:
        return True
    return any(parsed in network for network in _IGNORED_NETWORKS)


def extract_features(pkt) -> Optional[dict]:
    """
    Parse a Scapy IP packet into a flat feature dict.
    Returns None if the packet is not an IP packet or cannot be parsed.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
    except ImportError:
        return None

    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    if _should_ignore(ip_layer.src) or _should_ignore(ip_layer.dst):
        return None

    features: dict = {
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "pkt_len": len(pkt),
        "protocol": "other",
        "dst_port": None,
        "src_port": None,
        "flags": None,
        "is_syn": False,
        "is_ack": False,
        "is_rst": False,
        "timestamp": datetime.utcnow().isoformat(),
    }

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        features["protocol"] = "tcp"
        features["dst_port"] = tcp.dport
        features["src_port"] = tcp.sport
        flags = tcp.flags
        features["flags"] = str(flags)
        features["is_syn"] = bool(flags & 0x02) and not bool(flags & 0x10)  # SYN without ACK
        features["is_ack"] = bool(flags & 0x10)
        features["is_rst"] = bool(flags & 0x04)

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        features["protocol"] = "udp"
        features["dst_port"] = udp.dport
        features["src_port"] = udp.sport

    elif pkt.haslayer(ICMP):
        features["protocol"] = "icmp"

    return features
