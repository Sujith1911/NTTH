"""
Reporting Agent — persists ThreatEvents to DB and pushes WebSocket updates.
Subscribes to 'report_event' and 'device_seen'.
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
            device, created = await crud.get_or_create_device(db, payload.get("src_ip", "unknown"))

            # Upsert any enriched metadata from scanner/sniffer
            if any(payload.get(k) for k in ("mac_address", "hostname", "vendor")):
                device, _ = await crud.upsert_device_details(
                    db,
                    payload.get("src_ip", ""),
                    mac_address=payload.get("mac_address"),
                    hostname=payload.get("hostname"),
                    vendor=payload.get("vendor"),
                )

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

        from app.websocket.live_updates import broadcast

        # Broadcast full threat event — all fields required by frontend + test_realtime.py
        await broadcast({
            "type": "threat",
            "id": event.id,
            "event_id": event.id,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "dst_port": event.dst_port,
            "protocol": event.protocol,
            "threat_type": event.threat_type,
            "risk_score": event.risk_score,
            "action_taken": event.action_taken,
            "action": event.action_taken,
            "country": event.country,
            "city": event.city,
            "asn": event.asn,
            "org": event.org,
            "latitude": event.latitude,
            "longitude": event.longitude,
            "lat": event.latitude,
            "lon": event.longitude,
            "detected_at": event.detected_at.isoformat() if event.detected_at else None,
            "acknowledged": event.acknowledged,
        })

        # Real-time device risk update for Devices screen
        await broadcast({
            "type": "device_updated",
            "ip": payload.get("src_ip"),
            "risk_score": payload.get("risk_score", 0.0),
            "country": payload.get("country"),
            "city": payload.get("city"),
            "action": payload.get("action"),
        })

    except Exception as exc:
        log.error("reporting_agent.error", error=str(exc))


async def _handle_device_seen_ws(payload: dict) -> None:
    """Forward ARP-discovered devices to WS so the topology map updates live."""
    if payload.get("protocol") != "arp_scan":
        return   # only forward network scanner discoveries, not every captured packet
    from app.websocket.live_updates import broadcast
    try:
        await broadcast({
            "type": "device_seen",
            "ip": payload.get("src_ip"),
            "mac": payload.get("mac_address"),
            "hostname": payload.get("hostname"),
            "vendor": payload.get("vendor"),
            "timestamp": payload.get("timestamp"),
        })
    except Exception as exc:
        log.debug("reporting_agent.broadcast_device_seen_failed", error=str(exc))


event_bus.subscribe("report_event", _handle_report_event)
event_bus.subscribe("device_seen", _handle_device_seen_ws)
