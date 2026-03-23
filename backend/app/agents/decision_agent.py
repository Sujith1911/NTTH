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

    if protocol == "tcp":
        honeypot_port = settings.cowrie_redirect_port if dst_port in {21, 22, 23, 3389, 5900} else settings.http_honeypot_port
        return "honeypot", "redirect_and_hide_target", honeypot_port

    if base_action in {"honeypot", "block"}:
        return "block", "quarantine_source", None
    return "rate_limit", "observe_and_throttle", None


async def _handle_threat_detected(payload: dict) -> None:
    src_ip = payload.get("src_ip", "")
    risk_score = payload.get("risk_score", 0.0)

    # Never act on gateway IP
    if src_ip == settings.gateway_ip:
        log.debug("decision_agent.skipped_gateway", ip=src_ip)
        return

    base_action = determine_action(risk_score)
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

    await event_bus.publish("enforcement_action", {
        **payload,
        "action": action,
        "base_action": base_action,
        "incident_context": incident_context,
        "incident_notes": json.dumps(incident_context),
    })


event_bus.subscribe("threat_detected", _handle_threat_detected)
