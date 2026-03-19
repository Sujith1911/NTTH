"""
Decision Agent — subscribes to 'threat_detected', makes enforcement decisions,
publishes 'enforcement_action' for the Enforcement Agent.
"""
from __future__ import annotations

from app.config import get_settings
from app.core import event_bus
from app.core.logger import get_logger
from app.ids.risk_calculator import determine_action

log = get_logger("decision_agent")
settings = get_settings()


async def _handle_threat_detected(payload: dict) -> None:
    src_ip = payload.get("src_ip", "")
    risk_score = payload.get("risk_score", 0.0)

    # Never act on gateway IP
    if src_ip == settings.gateway_ip:
        log.debug("decision_agent.skipped_gateway", ip=src_ip)
        return

    action = determine_action(risk_score)

    log.info(
        "decision_agent.decision",
        src_ip=src_ip,
        risk_score=risk_score,
        action=action,
        threat_type=payload.get("threat_type"),
    )

    await event_bus.publish("enforcement_action", {
        **payload,
        "action": action,
    })


event_bus.subscribe("threat_detected", _handle_threat_detected)
