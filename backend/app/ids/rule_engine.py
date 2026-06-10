"""
Rule-based IDS engine.
Detects: port scanning, host sweeps, ARP sweeps, stealth scans, SYN flood, brute force.
Uses bounded sliding windows per source IP stored in-memory.
Returns a rule_score in [0.0, 1.0].

Memory safety:
  - Each deque has a maxlen cap so individual IPs can't cause OOM.
  - _prune_stale_keys() removes IPs with no activity in 5 minutes
    once total tracked IPs exceed _MAX_TRACKED_IPS.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from app.core.logger import get_logger
from app.ids.threshold_config import THRESHOLDS

log = get_logger("rule_engine")

# Ports that normal client devices legitimately connect to — never count these as scan targets
_COMMON_SERVICE_PORTS = {
    53, 80, 123, 443, 853, 993, 995,
    5222, 5223, 5228, 5229, 5230,  # Google Play, FCM push
    8080, 8443,                     # alt HTTP/HTTPS
    4500, 500,                      # IPSec/VPN
}

# ── Memory safety constants ──────────────────────────────────────────────────
_PORT_WINDOW_MAXLEN = 500       # Max entries per IP for port scan tracking
_TARGET_WINDOW_MAXLEN = 500     # Max entries per IP for target sweep tracking
_ARP_WINDOW_MAXLEN = 500        # Max entries per IP for ARP sweep tracking
_STEALTH_WINDOW_MAXLEN = 100    # Max entries per IP for stealth flag tracking
_SYN_WINDOW_MAXLEN = 200        # Max entries per IP for SYN flood tracking
_BRUTE_WINDOW_MAXLEN = 200      # Max entries per IP for brute force tracking
_MAX_TRACKED_IPS = 5_000        # Trigger stale-key pruning above this
_STALE_SECONDS = 300            # 5 min — remove keys idle longer than this
_last_prune_time: float = 0.0

# Sliding windows: ip → deque of (timestamp, value)
# Each deque has a maxlen to prevent unbounded growth per-IP
_port_windows: dict[str, deque[tuple[float, int]]] = defaultdict(
    lambda: deque(maxlen=_PORT_WINDOW_MAXLEN)
)
_target_windows: dict[str, deque[tuple[float, str]]] = defaultdict(
    lambda: deque(maxlen=_TARGET_WINDOW_MAXLEN)
)
_arp_windows: dict[str, deque[tuple[float, str]]] = defaultdict(
    lambda: deque(maxlen=_ARP_WINDOW_MAXLEN)
)
_stealth_windows: dict[str, deque[tuple[float, str]]] = defaultdict(
    lambda: deque(maxlen=_STEALTH_WINDOW_MAXLEN)
)
_syn_windows: dict[str, deque[float]] = defaultdict(
    lambda: deque(maxlen=_SYN_WINDOW_MAXLEN)
)
_brute_windows: dict[str, deque[float]] = defaultdict(
    lambda: deque(maxlen=_BRUTE_WINDOW_MAXLEN)
)

# Brute-force auth ports
_AUTH_PORTS = {22, 23, 3389, 5900, 21, 3306, 5432, 1521}


def _prune_stale_keys() -> None:
    """Remove IPs with no recent activity to cap total memory usage."""
    global _last_prune_time
    now = time.monotonic()
    # Only prune every 30 seconds and when we exceed the threshold
    total_keys = (
        len(_port_windows)
        + len(_target_windows)
        + len(_arp_windows)
        + len(_stealth_windows)
        + len(_syn_windows)
        + len(_brute_windows)
    )
    if total_keys < _MAX_TRACKED_IPS or (now - _last_prune_time) < 30:
        return
    _last_prune_time = now
    cutoff = now - _STALE_SECONDS
    pruned = 0
    for store in (_port_windows, _target_windows, _arp_windows, _stealth_windows, _syn_windows, _brute_windows):
        stale = [
            ip for ip, dq in store.items()
            if not dq or (dq[-1][0] if isinstance(dq[-1], tuple) else dq[-1]) < cutoff
        ]
        for ip in stale:
            del store[ip]
            pruned += 1
    if pruned:
        log.info("rule_engine.pruned_stale_keys", count=pruned)


# ── Detectors ────────────────────────────────────────────────────────────────

def _detect_port_scan(src_ip: str, dst_port: int | None) -> tuple[float, dict]:
    """Score = 1.0 if >N unique ports in window, else 0."""
    if dst_port is None:
        return 0.0, {"rule": "port_scan", "matched": False, "reason": "No destination port"}
    # Common service ports (HTTPS, DNS, etc.) are not scan indicators
    if dst_port in _COMMON_SERVICE_PORTS:
        return 0.0, {"rule": "port_scan", "matched": False, "reason": "Common service port"}
    now = time.monotonic()
    window = _port_windows[src_ip]
    # Prune old entries
    cutoff = now - THRESHOLDS.port_scan_window_seconds
    while window and window[0][0] < cutoff:
        window.popleft()
    window.append((now, dst_port))
    ports = sorted({p for _, p in window})
    unique_ports = len(ports)
    detail = {
        "rule": "port_scan",
        "matched": unique_ports >= THRESHOLDS.port_scan_unique_ports,
        "unique_ports": unique_ports,
        "threshold": THRESHOLDS.port_scan_unique_ports,
        "window_seconds": THRESHOLDS.port_scan_window_seconds,
        "ports": ports[-20:],
    }
    if unique_ports >= THRESHOLDS.port_scan_unique_ports:
        log.warning("ids.port_scan", src_ip=src_ip, unique_ports=unique_ports)
        return 1.0, detail
    return min(unique_ports / THRESHOLDS.port_scan_unique_ports, 0.8), detail


def _detect_host_sweep(src_ip: str, dst_ip: str | None, protocol: str | None, dst_port: int | None) -> tuple[float, dict]:
    """Detect discovery across many hosts, including nmap ping/port sweeps."""
    if not dst_ip or protocol not in {"tcp", "udp", "icmp"}:
        return 0.0, {"rule": "host_sweep", "matched": False, "reason": "No IP host probe"}
    # Repeated DNS/HTTPS to public endpoints should not look like LAN host discovery.
    if protocol in {"tcp", "udp"} and dst_port in {53, 80, 123, 443, 853, 5228, 5229, 5230}:
        return 0.0, {"rule": "host_sweep", "matched": False, "reason": "Common client service"}
    # ICMP to public/external IPs is normal browsing behavior (traceroute, CDN pings).
    # Host sweeps only target local LAN subnets.
    if protocol == "icmp" and not dst_ip.startswith("192.168.") and not dst_ip.startswith("10.") and not dst_ip.startswith("172."):
        return 0.0, {"rule": "host_sweep", "matched": False, "reason": "ICMP to public IP (normal browsing)"}
    now = time.monotonic()
    window = _target_windows[src_ip]
    cutoff = now - THRESHOLDS.port_scan_window_seconds
    while window and window[0][0] < cutoff:
        window.popleft()
    window.append((now, dst_ip))
    targets = sorted({target for _, target in window})
    unique_targets = len(targets)
    detail = {
        "rule": "host_sweep",
        "matched": unique_targets >= THRESHOLDS.host_sweep_unique_targets,
        "unique_targets": unique_targets,
        "threshold": THRESHOLDS.host_sweep_unique_targets,
        "window_seconds": THRESHOLDS.port_scan_window_seconds,
        "targets": targets[-20:],
    }
    if unique_targets >= THRESHOLDS.host_sweep_unique_targets:
        log.warning("ids.host_sweep", src_ip=src_ip, unique_targets=unique_targets)
        return 1.0, detail
    return min(unique_targets / THRESHOLDS.host_sweep_unique_targets, 0.8), detail


def _detect_arp_sweep(src_ip: str, arp_target_ip: str | None, is_arp_request: bool) -> tuple[float, dict]:
    """Detect ARP discovery sweeps such as nmap -PR or arp-scan."""
    if not is_arp_request or not arp_target_ip:
        return 0.0, {"rule": "arp_sweep", "matched": False, "reason": "Not an ARP request"}
    # ARP for the gateway is completely normal — every device does this
    from app.config import get_settings
    _gw = get_settings().gateway_ip
    if arp_target_ip == _gw:
        return 0.0, {"rule": "arp_sweep", "matched": False, "reason": "ARP for gateway (normal)"}
    now = time.monotonic()
    window = _arp_windows[src_ip]
    cutoff = now - THRESHOLDS.port_scan_window_seconds
    while window and window[0][0] < cutoff:
        window.popleft()
    window.append((now, arp_target_ip))
    targets = sorted({target for _, target in window})
    unique_targets = len(targets)
    detail = {
        "rule": "arp_sweep",
        "matched": unique_targets >= THRESHOLDS.arp_sweep_unique_targets,
        "unique_targets": unique_targets,
        "threshold": THRESHOLDS.arp_sweep_unique_targets,
        "window_seconds": THRESHOLDS.port_scan_window_seconds,
        "targets": targets[-20:],
    }
    if unique_targets >= THRESHOLDS.arp_sweep_unique_targets:
        log.warning("ids.arp_sweep", src_ip=src_ip, unique_targets=unique_targets)
        return 1.0, detail
    return min(unique_targets / THRESHOLDS.arp_sweep_unique_targets, 0.8), detail


def _detect_stealth_scan(src_ip: str, protocol: str | None, flags: str | None) -> tuple[float, dict]:
    """Detect NULL/FIN/XMAS-like nmap probes and OS-detection flag anomalies."""
    # Stealth scans only apply to TCP — UDP/ICMP/ARP packets must be excluded immediately
    if protocol != "tcp":
        return 0.0, {"rule": "stealth_scan", "matched": False, "reason": "Not TCP; stealth scan N/A"}
    normalized = (flags or "").strip()
    # Normal TCP flag patterns are safe
    if normalized in {"S", "SA", "A", "PA", "FA", "RA", "R"}:
        return 0.0, {"rule": "stealth_scan", "matched": False, "reason": "Common TCP flag pattern"}
    suspicious = False
    if normalized == "":
        suspicious = True  # NULL scan (TCP with no flags set)
    else:
        flag_set = set(normalized)
        suspicious = bool(flag_set & {"F", "P", "U"}) and "S" not in flag_set and "A" not in flag_set
    if not suspicious:
        return 0.0, {"rule": "stealth_scan", "matched": False, "reason": "Not a stealth flag pattern"}
    now = time.monotonic()
    window = _stealth_windows[src_ip]
    cutoff = now - THRESHOLDS.port_scan_window_seconds
    while window and window[0][0] < cutoff:
        window.popleft()
    window.append((now, normalized or "NULL"))
    attempts = len(window)
    detail = {
        "rule": "stealth_scan",
        "matched": attempts >= THRESHOLDS.stealth_scan_attempts,
        "attempts": attempts,
        "threshold": THRESHOLDS.stealth_scan_attempts,
        "window_seconds": THRESHOLDS.port_scan_window_seconds,
        "flags": [flag for _, flag in list(window)[-10:]],
    }
    if attempts >= THRESHOLDS.stealth_scan_attempts:
        log.warning("ids.stealth_scan", src_ip=src_ip, attempts=attempts)
        return 1.0, detail
    return min(attempts / THRESHOLDS.stealth_scan_attempts, 0.8), detail


def _detect_syn_flood(src_ip: str, is_syn: bool) -> tuple[float, dict]:
    """Score = 1.0 if SYN rate > threshold per second."""
    if not is_syn:
        return 0.0, {"rule": "syn_flood", "matched": False, "reason": "Packet is not SYN-only"}
    now = time.monotonic()
    window = _syn_windows[src_ip]
    window.append(now)
    cutoff = now - 1.0  # 1-second window
    while window and window[0] < cutoff:
        window.popleft()
    rate = len(window)
    detail = {
        "rule": "syn_flood",
        "matched": rate >= THRESHOLDS.syn_flood_per_second,
        "syns_per_second": rate,
        "threshold": THRESHOLDS.syn_flood_per_second,
        "window_seconds": 1,
    }
    if rate >= THRESHOLDS.syn_flood_per_second:
        log.warning("ids.syn_flood", src_ip=src_ip, rate=rate)
        return 1.0, detail
    return min(rate / THRESHOLDS.syn_flood_per_second, 0.8), detail


def _detect_brute_force(src_ip: str, dst_port: int | None, is_syn: bool) -> tuple[float, dict]:
    """Score = 1.0 if auth port packet rate > threshold in window.

    Counts ALL packets to auth ports (not just SYN) because SSH is encrypted
    and password attempts are invisible at the network layer. A single SSH
    session generates ~15 packets for setup + ~5 per password attempt.
    """
    if dst_port not in _AUTH_PORTS:
        return 0.0, {"rule": "brute_force", "matched": False, "reason": "Not an auth service port"}
    now = time.monotonic()
    window = _brute_windows[src_ip]
    window.append(now)
    cutoff = now - THRESHOLDS.brute_force_window_seconds
    while window and window[0] < cutoff:
        window.popleft()
    attempts = len(window)
    detail = {
        "rule": "brute_force",
        "matched": attempts >= THRESHOLDS.brute_force_attempts,
        "attempts": attempts,
        "threshold": THRESHOLDS.brute_force_attempts,
        "window_seconds": THRESHOLDS.brute_force_window_seconds,
        "port": dst_port,
    }
    if attempts >= THRESHOLDS.brute_force_attempts:
        log.warning("ids.brute_force", src_ip=src_ip, port=dst_port, attempts=attempts)
        return 1.0, detail
    return min(attempts / THRESHOLDS.brute_force_attempts, 0.8), detail


# ── Public interface ──────────────────────────────────────────────────────────

def evaluate(features: dict) -> dict:
    """
    Evaluate a feature dict against all rules.
    Returns {rule_score, threat_type, details}.
    """
    # Periodically prune stale IP keys to prevent memory growth
    _prune_stale_keys()

    src_ip = features.get("src_ip", "")
    dst_ip = features.get("dst_ip")
    protocol = features.get("protocol")
    dst_port = features.get("dst_port")
    is_syn = features.get("is_syn", False)
    flags = features.get("flags")

    port_score, port_detail = _detect_port_scan(src_ip, dst_port)
    host_score, host_detail = _detect_host_sweep(src_ip, dst_ip, protocol, dst_port)
    arp_score, arp_detail = _detect_arp_sweep(src_ip, features.get("arp_target_ip"), bool(features.get("is_arp_request")))
    stealth_score, stealth_detail = _detect_stealth_scan(src_ip, protocol, flags)
    syn_score, syn_detail = _detect_syn_flood(src_ip, is_syn)
    brute_score, brute_detail = _detect_brute_force(src_ip, dst_port, is_syn)

    rule_score = max(port_score, host_score, arp_score, stealth_score, syn_score, brute_score)

    threat_type = "normal"
    if rule_score >= 0.9:
        if port_score >= 0.9:
            threat_type = "port_scan"
        elif host_score >= 0.9:
            threat_type = "host_sweep"
        elif arp_score >= 0.9:
            threat_type = "arp_sweep"
        elif stealth_score >= 0.9:
            threat_type = "stealth_scan"
        elif syn_score >= 0.9:
            threat_type = "syn_flood"
        elif brute_score >= 0.9:
            threat_type = "brute_force"
    elif rule_score > 0:
        threat_type = "suspicious"

    return {
        "rule_score": round(rule_score, 4),
        "threat_type": threat_type,
        "port_score": round(port_score, 4),
        "host_score": round(host_score, 4),
        "arp_score": round(arp_score, 4),
        "stealth_score": round(stealth_score, 4),
        "syn_score": round(syn_score, 4),
        "brute_score": round(brute_score, 4),
        "rule_details": {
            "port_scan": port_detail,
            "host_sweep": host_detail,
            "arp_sweep": arp_detail,
            "stealth_scan": stealth_detail,
            "syn_flood": syn_detail,
            "brute_force": brute_detail,
            "winning_rule": (
                "port_scan" if port_score == rule_score and rule_score > 0 else
                "host_sweep" if host_score == rule_score and rule_score > 0 else
                "arp_sweep" if arp_score == rule_score and rule_score > 0 else
                "stealth_scan" if stealth_score == rule_score and rule_score > 0 else
                "syn_flood" if syn_score == rule_score and rule_score > 0 else
                "brute_force" if brute_score == rule_score and rule_score > 0 else
                "none"
            ),
        },
    }
