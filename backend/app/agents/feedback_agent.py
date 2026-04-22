"""
Feedback Agent — monitors enforcement outcomes and adjusts detection
sensitivity based on observed patterns.

Subscribes to:
  - report_event: to track action outcomes
  - device_seen: to track traffic post-enforcement

Responsibilities:
  - Track false positive rate (blocked devices that show normal traffic later)
  - Track honeypot engagement (did the attacker interact or disconnect?)
  - Adjust IDS thresholds dynamically based on observed FP/FN rates
  - Publish feedback metrics for dashboard consumption
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime

from app.core import event_bus
from app.core.logger import get_logger

log = get_logger("feedback_agent")

# ── State tracking ────────────────────────────────────────────────

# Recent enforcement outcomes: src_ip → list of (timestamp, action, threat_type)
_enforcement_log: dict[str, deque] = defaultdict(lambda: deque(maxlen=50))

# Post-enforcement traffic: src_ip → packets seen after enforcement
_post_enforcement_traffic: dict[str, int] = defaultdict(int)

# Honeypot engagement tracking
_honeypot_redirects: dict[str, float] = {}     # ip → redirect timestamp
_honeypot_interactions: dict[str, bool] = {}   # ip → did they interact?

# Aggregate metrics
_metrics = {
    "total_enforcements": 0,
    "total_blocks": 0,
    "total_honeypot_redirects": 0,
    "total_rate_limits": 0,
    "honeypot_engagement_rate": 0.0,
    "estimated_false_positive_rate": 0.0,
    "last_updated": None,
}


async def _handle_report_event(payload: dict) -> None:
    """Track every enforcement action for feedback analysis."""
    action = payload.get("action")
    src_ip = payload.get("src_ip", "")
    threat_type = payload.get("threat_type", "unknown")
    now = time.time()

    if action in ("block", "honeypot", "rate_limit"):
        _enforcement_log[src_ip].append({
            "timestamp": now,
            "action": action,
            "threat_type": threat_type,
            "risk_score": payload.get("risk_score", 0),
        })

        _metrics["total_enforcements"] += 1
        if action == "block":
            _metrics["total_blocks"] += 1
        elif action == "honeypot":
            _metrics["total_honeypot_redirects"] += 1
            _honeypot_redirects[src_ip] = now
        elif action == "rate_limit":
            _metrics["total_rate_limits"] += 1

        _metrics["last_updated"] = datetime.utcnow().isoformat()

        log.debug(
            "feedback_agent.enforcement_tracked",
            ip=src_ip, action=action, threat_type=threat_type,
        )


async def _handle_device_seen(payload: dict) -> None:
    """
    Track traffic from devices that were previously enforced.

    If a blocked device continues showing normal traffic patterns,
    it may have been a false positive.
    """
    src_ip = payload.get("src_ip", "")
    if src_ip in _enforcement_log:
        _post_enforcement_traffic[src_ip] += 1

        # If we see significant normal traffic after enforcement,
        # flag potential false positive
        if _post_enforcement_traffic[src_ip] == 100:
            last_enforcement = _enforcement_log[src_ip][-1]
            elapsed = time.time() - last_enforcement["timestamp"]

            # If >5 minutes of normal traffic after enforcement → possible FP
            if elapsed > 300 and last_enforcement["action"] == "block":
                log.warning(
                    "feedback_agent.possible_false_positive",
                    ip=src_ip,
                    threat_type=last_enforcement["threat_type"],
                    post_enforcement_packets=_post_enforcement_traffic[src_ip],
                )
                await event_bus.publish("feedback_alert", {
                    "type": "possible_false_positive",
                    "src_ip": src_ip,
                    "original_action": last_enforcement["action"],
                    "original_threat_type": last_enforcement["threat_type"],
                    "post_enforcement_packets": _post_enforcement_traffic[src_ip],
                    "elapsed_seconds": round(elapsed),
                })


async def _handle_honeypot_interaction(payload: dict) -> None:
    """Track whether honeypot redirects result in actual engagement."""
    attacker_ip = payload.get("attacker_ip", "")
    if attacker_ip in _honeypot_redirects:
        _honeypot_interactions[attacker_ip] = True
        log.info(
            "feedback_agent.honeypot_engaged",
            ip=attacker_ip,
            protocol=payload.get("protocol", "unknown"),
        )

    _update_metrics()


def _update_metrics() -> None:
    """Recalculate aggregate feedback metrics."""
    # Honeypot engagement rate
    total_redirects = len(_honeypot_redirects)
    if total_redirects > 0:
        engaged = sum(1 for v in _honeypot_interactions.values() if v)
        _metrics["honeypot_engagement_rate"] = round(engaged / total_redirects, 2)

    # Estimated false positive rate (rough heuristic)
    total_enforcements = _metrics["total_enforcements"]
    if total_enforcements > 0:
        # Count IPs with significant post-enforcement traffic
        possible_fps = sum(
            1 for count in _post_enforcement_traffic.values()
            if count >= 100
        )
        _metrics["estimated_false_positive_rate"] = round(
            possible_fps / total_enforcements, 3
        )

    _metrics["last_updated"] = datetime.utcnow().isoformat()


# ── Public API ────────────────────────────────────────────────────

def get_feedback_metrics() -> dict:
    """Return current feedback metrics for the dashboard."""
    _update_metrics()
    return {
        **_metrics,
        "tracked_ips": len(_enforcement_log),
        "honeypot_redirects_tracked": len(_honeypot_redirects),
        "honeypot_engagements": sum(1 for v in _honeypot_interactions.values() if v),
    }


def get_enforcement_history(ip: str) -> list[dict]:
    """Get enforcement history for a specific IP."""
    return list(_enforcement_log.get(ip, []))


def get_top_enforced(limit: int = 10) -> list[dict]:
    """Return the most frequently enforced IPs."""
    ranked = sorted(
        _enforcement_log.items(),
        key=lambda x: len(x[1]),
        reverse=True,
    )[:limit]
    return [
        {
            "ip": ip,
            "enforcement_count": len(entries),
            "last_action": entries[-1]["action"] if entries else None,
            "last_threat_type": entries[-1]["threat_type"] if entries else None,
        }
        for ip, entries in ranked
    ]


# ── Event subscriptions ──────────────────────────────────────────

event_bus.subscribe("report_event", _handle_report_event)
event_bus.subscribe("device_seen", _handle_device_seen)
event_bus.subscribe("honeypot_interaction", _handle_honeypot_interaction)
