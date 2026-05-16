"""
Extract security-relevant features from a raw Scapy packet.
Returns a dict suitable for IDS scoring and device registry.
"""
from __future__ import annotations

from ipaddress import ip_address, ip_network
import json
from typing import Optional
from urllib.parse import parse_qsl

from app.config import get_settings
from app.core.time_utils import local_now_iso

settings = get_settings()
_IGNORED_NETWORKS = tuple(ip_network(cidr) for cidr in settings.ignored_monitor_cidrs)


def _should_ignore(ip: str) -> bool:
    try:
        parsed = ip_address(ip)
    except ValueError:
        return True
    # Skip multicast, broadcast, and network addresses
    if parsed.is_multicast or str(parsed).endswith(".255") or str(parsed).endswith(".0"):
        return True
    return any(parsed in network for network in _IGNORED_NETWORKS)


def _direction(src_ip: str, dst_ip: str) -> str:
    network = None
    if settings.scan_subnet:
        try:
            network = ip_network(settings.scan_subnet, strict=False)
        except ValueError:
            network = None
    if network is None:
        return "external"
    try:
        src_local = ip_address(src_ip) in network
        dst_local = ip_address(dst_ip) in network
    except ValueError:
        return "external"
    if src_local and dst_local:
        return "internal"
    if src_local:
        return "outbound"
    if dst_local:
        return "inbound"
    return "external"


def _payload_bytes(pkt) -> bytes:
    try:
        from scapy.packet import Raw  # type: ignore
    except ImportError:
        return b""
    if not pkt.haslayer(Raw):
        return b""
    return bytes(pkt[Raw].load or b"")


def _decode_payload(payload: bytes) -> str | None:
    if not payload:
        return None
    try:
        return payload[:4096].decode("utf-8", errors="replace")
    except Exception:
        return None


def _http_details(payload: bytes, src_port: int | None, dst_port: int | None) -> dict:
    http_ports = {80, 8080, 8888}
    if src_port not in http_ports and dst_port not in http_ports:
        return {}
    text = _decode_payload(payload)
    if not text:
        return {}

    first_line = text.split("\r\n", 1)[0]
    methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    parts = first_line.split()
    if len(parts) < 2 or parts[0] not in methods:
        return {}

    header_blob, _, body = text.partition("\r\n\r\n")
    headers: dict[str, str] = {}
    for line in header_blob.split("\r\n")[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    content_type = headers.get("content-type", "")
    form_fields: dict[str, str] = {}
    if body and "application/x-www-form-urlencoded" in content_type:
        form_fields = {key: value for key, value in parse_qsl(body, keep_blank_values=True)}

    return {
        "http_method": parts[0],
        "http_path": parts[1],
        "http_host": headers.get("host"),
        "http_user_agent": headers.get("user-agent"),
        "http_content_type": content_type or None,
        "http_body_preview": body[:2048] if body else None,
        "http_form_fields": json.dumps(form_fields) if form_fields else None,
    }


def _json_safe(value):
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def extract_features(pkt) -> Optional[dict]:
    """
    Parse a Scapy IP packet into a flat feature dict.
    Returns None if the packet is not an IP packet or cannot be parsed.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore
    except ImportError:
        return None

    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    if _should_ignore(ip_layer.src) or _should_ignore(ip_layer.dst):
        return None

    payload = _payload_bytes(pkt)
    payload_len = len(payload)
    payload_hex = payload[:512].hex() if payload else None
    payload_text = _decode_payload(payload)
    features: dict = {
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "pkt_len": len(pkt),
        "payload_len": payload_len,
        "payload_preview": payload_hex,
        "payload_text": payload_text,
        "direction": _direction(ip_layer.src, ip_layer.dst),
        "src_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
        "dst_mac": pkt[Ether].dst if pkt.haslayer(Ether) else None,
        "ip_version": getattr(ip_layer, "version", None),
        "ip_ttl": getattr(ip_layer, "ttl", None),
        "ip_tos": getattr(ip_layer, "tos", None),
        "ip_id": getattr(ip_layer, "id", None),
        "ip_flags": str(getattr(ip_layer, "flags", "")) or None,
        "frag_offset": getattr(ip_layer, "frag", None),
        "protocol": "other",
        "dst_port": None,
        "src_port": None,
        "flags": None,
        "is_syn": False,
        "is_ack": False,
        "is_rst": False,
        "timestamp": local_now_iso(),
    }

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        features["protocol"] = "tcp"
        features["dst_port"] = tcp.dport
        features["src_port"] = tcp.sport
        flags = tcp.flags
        features["flags"] = str(flags)
        features["tcp_seq"] = tcp.seq
        features["tcp_ack"] = tcp.ack
        features["tcp_window"] = tcp.window
        features["tcp_options"] = json.dumps(tcp.options or [], default=_json_safe)
        features["is_syn"] = bool(flags & 0x02) and not bool(flags & 0x10)  # SYN without ACK
        features["is_ack"] = bool(flags & 0x10)
        features["is_rst"] = bool(flags & 0x04)
        features.update(_http_details(payload, tcp.sport, tcp.dport))

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        features["protocol"] = "udp"
        features["dst_port"] = udp.dport
        features["src_port"] = udp.sport
        features["udp_len"] = udp.len

    elif pkt.haslayer(ICMP):
        features["protocol"] = "icmp"
        icmp = pkt[ICMP]
        features["icmp_type"] = icmp.type
        features["icmp_code"] = icmp.code

    return features
