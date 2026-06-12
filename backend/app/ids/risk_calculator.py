"""
Risk calculator — combines rule_score and ml_score into a final risk score.
Formula: risk = 0.6 * rule_score + 0.4 * ml_score

Tracks per-IP scan counts to escalate repeat scanners from honeypot to block.
"""
from __future__ import annotations

from collections import defaultdict

from app.ids.threshold_config import THRESHOLDS


# ── Per-IP scan counter for escalation ──
_scan_counts: dict[str, int] = defaultdict(int)
_SCAN_BLOCK_THRESHOLD = 6  # Block after 6+ scan events from same IP


def calculate(rule_score: float, ml_score: float) -> float:
    """Return weighted risk score in [0.0, 1.0]. Boost confident rule matches to 0.90.

    The boost caps at 0.90 (not 0.95) to keep rule-confirmed attacks in the
    honeypot zone (0.75–0.95) rather than immediately hitting the block
    threshold (0.95). Only truly extreme threats should reach block level.
    """
    risk = THRESHOLDS.rule_weight * rule_score + THRESHOLDS.ml_weight * ml_score
    if rule_score >= 1.0:
        risk = max(risk, 0.90)
    return round(min(max(risk, 0.0), 1.0), 4)


def determine_action(risk_score: float, threat_type: str = "normal", src_ip: str = "") -> str:
    """
    Map risk score and threat type to a decision string.
    log | rate_limit | honeypot | block

    Tracks scan counts per IP. After 6+ scans, escalates to block.
    SSH brute force always redirects to honeypot (blocking handled
    by session_logger after 10+ honeypot interactions).
    """
    # Honeypot interactions — attacker is ALREADY trapped, don't block them
    # (session_logger handles escalation to block after 10+ sessions)
    if threat_type in {"honeypot_ssh", "honeypot_http", "honeypot_interaction"}:
        return "log"

    # Scan-type attacks — track count, escalate after threshold
    if threat_type in {"port_scan", "host_sweep", "stealth_scan"}:
        if src_ip:
            _scan_counts[src_ip] += 1
            if _scan_counts[src_ip] >= _SCAN_BLOCK_THRESHOLD:
                return "block"
        return "honeypot"

    # SSH brute force — always redirect to honeypot for deception
    if threat_type in {"brute_force"}:
        return "honeypot"

    # Flood / sweep attacks → block immediately (can't interact with honeypot)
    if threat_type in {"syn_flood", "icmp_flood", "arp_sweep"}:
        return "block"

    if risk_score >= THRESHOLDS.block_threshold:
        return "block"
    if risk_score >= THRESHOLDS.honeypot_threshold:
        return "honeypot"
    if risk_score >= THRESHOLDS.rate_limit_threshold:
        return "rate_limit"
    if risk_score >= THRESHOLDS.log_threshold:
        return "log"
    return "allow"


def get_scan_count(ip: str) -> int:
    """Return current scan count for an IP (for dashboard/logging)."""
    return _scan_counts.get(ip, 0)


def reset_scan_count(ip: str) -> None:
    """Reset scan count for an IP (when unblocked via dashboard)."""
    _scan_counts.pop(ip, None)
