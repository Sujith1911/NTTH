"""
Threat Agent — first stage in the agentic pipeline.
Subscribes to 'device_seen' events, runs IDS, enriches with GeoIP,
then publishes a 'threat_detected' event for the Decision Agent.
"""
from __future__ import annotations

from app.core import event_bus
from app.core.logger import get_logger
from app.ids import rule_engine, anomaly_model
from app.ids.risk_calculator import calculate, determine_action
from app.monitor import device_registry

log = get_logger("threat_agent")


async def _handle_device_seen(features: dict) -> None:
    """Process each captured packet's features through the IDS pipeline."""
    # Update device registry
    device_state = device_registry.update(features)

    # Rule-based scoring
    rule_result = rule_engine.evaluate(features)

    # ML anomaly scoring
    ml_score = anomaly_model.score(features)

    # Risk calculation
    risk_score = calculate(rule_result["rule_score"], ml_score)
    action = determine_action(risk_score)

    # Only emit threat events above the log threshold
    if action == "allow":
        return

    # GeoIP enrichment (non-blocking, best-effort)
    geo_info = {}
    try:
        from app.geoip.geo_lookup import lookup
        geo_info = lookup(features.get("src_ip", ""))
    except Exception:
        pass

    threat_payload = {
        **features,
        **rule_result,
        "ml_score": ml_score,
        "risk_score": risk_score,
        "action": action,
        "device_state": device_state,
        **geo_info,
    }

    await event_bus.publish("threat_detected", threat_payload)

    if risk_score >= 0.7:
        log.warning(
            "threat_agent.high_risk",
            src_ip=features.get("src_ip"),
            risk_score=risk_score,
            action=action,
            threat_type=rule_result.get("threat_type"),
        )


# Subscribe at module import time
event_bus.subscribe("device_seen", _handle_device_seen)
