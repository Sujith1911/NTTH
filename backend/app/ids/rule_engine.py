"""
Rule-based IDS engine.
Detects: port scanning, SYN flood, brute force.
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

# ── Memory safety constants ──────────────────────────────────────────────────
_PORT_WINDOW_MAXLEN = 500       # Max entries per IP for port scan tracking
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
    total_keys = len(_port_windows) + len(_syn_windows) + len(_brute_windows)
    if total_keys < _MAX_TRACKED_IPS or (now - _last_prune_time) < 30:
        return
    _last_prune_time = now
    cutoff = now - _STALE_SECONDS
    pruned = 0
    for store in (_port_windows, _syn_windows, _brute_windows):
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

def _detect_port_scan(src_ip: str, dst_port: int | None) -> float:
    """Score = 1.0 if >N unique ports in window, else 0."""
    if dst_port is None:
        return 0.0
    now = time.monotonic()
    window = _port_windows[src_ip]
    # Prune old entries
    cutoff = now - THRESHOLDS.port_scan_window_seconds
    while window and window[0][0] < cutoff:
        window.popleft()
    window.append((now, dst_port))
    unique_ports = len({p for _, p in window})
    if unique_ports >= THRESHOLDS.port_scan_unique_ports:
        log.warning("ids.port_scan", src_ip=src_ip, unique_ports=unique_ports)
        return 1.0
    return min(unique_ports / THRESHOLDS.port_scan_unique_ports, 0.8)


def _detect_syn_flood(src_ip: str, is_syn: bool) -> float:
    """Score = 1.0 if SYN rate > threshold per second."""
    if not is_syn:
        return 0.0
    now = time.monotonic()
    window = _syn_windows[src_ip]
    window.append(now)
    cutoff = now - 1.0  # 1-second window
    while window and window[0] < cutoff:
        window.popleft()
    rate = len(window)
    if rate >= THRESHOLDS.syn_flood_per_second:
        log.warning("ids.syn_flood", src_ip=src_ip, rate=rate)
        return 1.0
    return min(rate / THRESHOLDS.syn_flood_per_second, 0.8)


def _detect_brute_force(src_ip: str, dst_port: int | None) -> float:
    """Score = 1.0 if auth port hit rate > threshold in window."""
    if dst_port not in _AUTH_PORTS:
        return 0.0
    now = time.monotonic()
    window = _brute_windows[src_ip]
    window.append(now)
    cutoff = now - THRESHOLDS.brute_force_window_seconds
    while window and window[0] < cutoff:
        window.popleft()
    attempts = len(window)
    if attempts >= THRESHOLDS.brute_force_attempts:
        log.warning("ids.brute_force", src_ip=src_ip, port=dst_port, attempts=attempts)
        return 1.0
    return min(attempts / THRESHOLDS.brute_force_attempts, 0.8)


# ── Public interface ──────────────────────────────────────────────────────────

def evaluate(features: dict) -> dict:
    """
    Evaluate a feature dict against all rules.
    Returns {rule_score, threat_type, details}.
    """
    # Periodically prune stale IP keys to prevent memory growth
    _prune_stale_keys()

    src_ip = features.get("src_ip", "")
    dst_port = features.get("dst_port")
    is_syn = features.get("is_syn", False)

    port_score = _detect_port_scan(src_ip, dst_port)
    syn_score = _detect_syn_flood(src_ip, is_syn)
    brute_score = _detect_brute_force(src_ip, dst_port)

    rule_score = max(port_score, syn_score, brute_score)

    threat_type = "normal"
    if rule_score >= 0.9:
        if port_score >= 0.9:
            threat_type = "port_scan"
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
        "syn_score": round(syn_score, 4),
        "brute_score": round(brute_score, 4),
    }
