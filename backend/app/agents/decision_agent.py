"""
Decision Agent — subscribes to 'threat_detected', makes enforcement decisions,
publishes 'enforcement_action' for the Enforcement Agent.
"""
from __future__ import annotations

import ipaddress
import json
import time

from app.config import get_settings
from app.core import event_bus
from app.core.logger import get_logger
from app.ids.risk_calculator import determine_action

log = get_logger("decision_agent")
settings = get_settings()
_CLOUD_HINTS = ("amazon", "aws", "google", "azure", "digitalocean", "linode", "ovh", "vultr", "oracle")
_RECENT_DECISIONS: dict[tuple[str, str, str], float] = {}
_DECISION_MAX_ENTRIES = 1_000   # Prune when dict exceeds this size
_DECISION_TTL_SECONDS = 60.0   # Evict entries older than this
_SSH_INTERCEPT_PORTS = {22}
_HTTP_INTERCEPT_PORTS = {80, 8080}
_DIRECT_HONEYPOT_PORTS = {settings.cowrie_redirect_port, settings.http_honeypot_port}


def _prune_recent_decisions() -> None:
    """Evict stale entries when the dedup dict grows too large."""
    if len(_RECENT_DECISIONS) <= _DECISION_MAX_ENTRIES:
        return
    now = time.monotonic()
    stale_keys = [
        k for k, ts in _RECENT_DECISIONS.items()
        if now - ts > _DECISION_TTL_SECONDS
    ]
    for k in stale_keys:
        del _RECENT_DECISIONS[k]
    if stale_keys:
        log.info("decision_agent.pruned_dedup", removed=len(stale_keys), remaining=len(_RECENT_DECISIONS))


def _network_origin(payload: dict) -> str:
    src_ip = payload.get("src_ip", "")
    org = (payload.get("org") or "").lower()
    asn = (payload.get("asn") or "").lower()
    try:
        parsed = ipaddress.ip_address(src_ip)
    except ValueError:
        return "unknown"

    if parsed.is_private:
        return "internal_lan"
    if any(hint in org or hint in asn for hint in _CLOUD_HINTS):
        return "cloud_vps_or_hosting"
    return "public_internet"


def _location_summary(payload: dict) -> str:
    city = payload.get("city")
    country = payload.get("country")
    org = payload.get("org")
    parts = [part for part in (city, country) if part]
    approx = ", ".join(parts) if parts else "unresolved"
    if org:
        return f"Approximate: {approx} via {org}"
    return f"Approximate: {approx}"


def _choose_response_action(payload: dict, base_action: str) -> tuple[str, str, int | None]:
    protocol = payload.get("protocol")
    dst_port = payload.get("dst_port")
    risk_score = float(payload.get("risk_score") or 0.0)

    # Service-interception policy:
    # Once a source becomes suspicious, SSH/HTTP traffic aimed at any protected
    # client is diverted into NTTH honeypots before the real service receives
    # follow-up attempts. Direct honeypot ports do not need redirection.
    if (
        protocol == "tcp"
        and risk_score >= settings.risk_rate_limit_threshold
        and dst_port not in _DIRECT_HONEYPOT_PORTS
        and dst_port in (_SSH_INTERCEPT_PORTS | _HTTP_INTERCEPT_PORTS)
    ):
        honeypot_port = (
            settings.cowrie_redirect_port
            if dst_port in _SSH_INTERCEPT_PORTS
            else settings.http_honeypot_port
        )
        return "honeypot", "intercept_service_to_honeypot", honeypot_port

    if base_action in {"allow", "log", "rate_limit"}:
        response = "observe" if base_action in {"allow", "log"} else "observe_and_throttle"
        return base_action, response, None

    _rule_detected_threats = {"brute_force", "port_scan", "host_sweep", "stealth_scan"}
    if base_action == "honeypot" and risk_score < 0.85 and payload.get("threat_type") not in _rule_detected_threats:
        return "rate_limit", "observe_and_throttle", None

    if base_action == "honeypot" and protocol == "tcp":
        honeypot_port = settings.cowrie_redirect_port if dst_port in {21, 22, 23, 3389, 5900} else settings.http_honeypot_port
        return "honeypot", "redirect_and_hide_target", honeypot_port

    if base_action == "block":
        return "block", "quarantine_source", None
    return "rate_limit", "observe_and_throttle", None


def _decision_reason(payload: dict, base_action: str, action: str, response_mode: str) -> str:
    risk_score = float(payload.get("risk_score") or 0.0)
    rule_details = payload.get("rule_details") or {}
    winning_rule = rule_details.get("winning_rule", "none")
    reasons = [
        f"risk_score={risk_score:.2f}",
        f"base_action={base_action}",
        f"final_action={action}",
        f"response_mode={response_mode}",
        f"winning_rule={winning_rule}",
    ]
    if base_action == "honeypot" and action == "rate_limit":
        reasons.append("honeypot_redirect_suppressed_until_risk>=0.85")
    if response_mode == "intercept_service_to_honeypot":
        reasons.append("protected_service_intercept_enabled")
    if action == "block":
        reasons.append("block_threshold_met")
    return "; ".join(reasons)


async def _handle_threat_detected(payload: dict) -> None:
    src_ip = payload.get("src_ip", "")
    risk_score = payload.get("risk_score", 0.0)

    # Periodically prune stale dedup entries
    _prune_recent_decisions()

    # Never act on gateway or our own server IP (our scanner generates port probes)
    _self_ips = {settings.gateway_ip, settings.server_display_ip}
    if src_ip in _self_ips:
        return

    base_action = determine_action(risk_score, payload.get("threat_type", "normal"))
    action, response_mode, honeypot_port = _choose_response_action(payload, base_action)
    victim_ip = payload.get("dst_ip")
    threat_type = payload.get("threat_type", "unknown")
    dedupe_key = (src_ip, victim_ip or "", threat_type)
    now = time.monotonic()
    last_seen = _RECENT_DECISIONS.get(dedupe_key)
    if last_seen is not None and now - last_seen < 2.0:
        return
    _RECENT_DECISIONS[dedupe_key] = now
    incident_context = {
        "source_tag": f"attacker::{src_ip.replace('.', '-')}",
        "victim_ip": victim_ip,
        "network_origin": _network_origin(payload),
        "location_accuracy": "approximate",
        "location_summary": _location_summary(payload),
        "response_mode": response_mode,
        "quarantine_target": bool(victim_ip),
        "target_hidden": action == "honeypot",
        "honeypot_port": honeypot_port,
        "tracked_commands": True,
        "response_priority": "aggressive",
        "decision_reason": _decision_reason(payload, base_action, action, response_mode),
        "risk_reasons": payload.get("risk_reasons", []),
        "rule_details": payload.get("rule_details", {}),
    }

    log.info(
        "decision_agent.decision",
        src_ip=src_ip,
        risk_score=risk_score,
        action=action,
        threat_type=threat_type,
        victim_ip=victim_ip,
        response_mode=response_mode,
    )

    action_payload = {
        **payload,
        "action": action,
        "base_action": base_action,
        "incident_context": incident_context,
        "incident_notes": json.dumps(incident_context),
    }
    try:
        from app.research.metrics import mark_decision
        mark_decision(action_payload)
    except Exception:
        pass

    await event_bus.publish("enforcement_action", action_payload)


event_bus.subscribe("threat_detected", _handle_threat_detected)
