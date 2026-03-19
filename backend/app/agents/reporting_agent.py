"""
Reporting Agent — persists ThreatEvents to DB and pushes WebSocket updates.
Subscribes to 'report_event'.
"""
from __future__ import annotations

from app.core import event_bus
from app.core.logger import get_logger
from app.database.session import AsyncSessionLocal
from app.database import crud

log = get_logger("reporting_agent")


async def _handle_report_event(payload: dict) -> None:
    try:
        async with AsyncSessionLocal() as db:
            # Ensure device exists
            device, _ = await crud.get_or_create_device(db, payload.get("src_ip", "unknown"))

            # Update device risk score
            await crud.update_device_risk(db, device.id, payload.get("risk_score", 0.0))

            # Create threat event
            event = await crud.create_threat_event(
                db,
                device_id=device.id,
                src_ip=payload.get("src_ip", ""),
                dst_ip=payload.get("dst_ip"),
                dst_port=payload.get("dst_port"),
                protocol=payload.get("protocol"),
                threat_type=payload.get("threat_type", "unknown"),
                risk_score=payload.get("risk_score", 0.0),
                rule_score=payload.get("rule_score"),
                ml_score=payload.get("ml_score"),
                action_taken=payload.get("action"),
                country=payload.get("country"),
                city=payload.get("city"),
                asn=payload.get("asn"),
                org=payload.get("org"),
                latitude=payload.get("latitude"),
                longitude=payload.get("longitude"),
            )
            await db.commit()

        # Push WebSocket update
        from app.websocket.live_updates import broadcast
        await broadcast({
            "type": "threat",
            "event_id": event.id,
            "src_ip": event.src_ip,
            "threat_type": event.threat_type,
            "risk_score": event.risk_score,
            "action": event.action_taken,
            "country": event.country,
            "lat": event.latitude,
            "lon": event.longitude,
        })

    except Exception as exc:
        log.error("reporting_agent.error", error=str(exc))


event_bus.subscribe("report_event", _handle_report_event)
