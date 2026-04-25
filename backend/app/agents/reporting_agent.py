"""
Reporting Agent — persists ThreatEvents to DB and pushes WebSocket updates.
Subscribes to 'report_event' and 'device_seen'.
"""
from __future__ import annotations

from app.core import event_bus
from app.core.logger import get_logger
from app.database.session import AsyncSessionLocal
from app.database import crud
from app.monitor.network_scanner import is_managed_asset_ip

log = get_logger("reporting_agent")


async def _handle_report_event(payload: dict) -> None:
    try:
        incident_context = payload.get("incident_context", {})
        victim_ip = (
            incident_context.get("victim_ip")
            or payload.get("dst_ip")
            or payload.get("src_ip")
        )
        managed_asset_ip = (
            victim_ip if isinstance(victim_ip, str) and is_managed_asset_ip(victim_ip) else None
        )
        async with AsyncSessionLocal() as db:
            device = None
            if managed_asset_ip:
                device, _ = await crud.upsert_device_details(db, managed_asset_ip)
                await crud.update_device_risk(db, device.id, payload.get("risk_score", 0.0))

            # Create threat event
            event = await crud.create_threat_event(
                db,
                device_id=device.id if device else None,
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
                notes=payload.get("incident_notes"),
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
            "source_tag": incident_context.get("source_tag"),
            "victim_ip": incident_context.get("victim_ip"),
            "response_mode": incident_context.get("response_mode"),
            "location_accuracy": incident_context.get("location_accuracy"),
            "location_summary": incident_context.get("location_summary"),
            "network_origin": incident_context.get("network_origin"),
            "target_hidden": incident_context.get("target_hidden"),
            "quarantine_target": incident_context.get("quarantine_target"),
            "honeypot_port": incident_context.get("honeypot_port"),
            "notes": event.notes,
        })

        # Real-time device risk update for Devices screen
        await broadcast({
            "type": "device_updated",
            "ip": managed_asset_ip,
            "risk_score": payload.get("risk_score", 0.0),
            "country": payload.get("country"),
            "city": payload.get("city"),
            "action": payload.get("action"),
        })

        await broadcast({
            "type": "incident_response",
            "src_ip": payload.get("src_ip"),
            "victim_ip": incident_context.get("victim_ip"),
            "threat_type": payload.get("threat_type"),
            "risk_score": payload.get("risk_score", 0.0),
            "action": payload.get("action"),
            "source_tag": incident_context.get("source_tag"),
            "response_mode": incident_context.get("response_mode"),
            "network_origin": incident_context.get("network_origin"),
            "location_summary": incident_context.get("location_summary"),
            "target_hidden": incident_context.get("target_hidden"),
            "honeypot_port": incident_context.get("honeypot_port"),
            "timestamp": payload.get("timestamp"),
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


# ── Packet persistence for user inspection ───────────────────────────────────
_packet_sample_counter = 0


async def _persist_packet(payload: dict, threat_type: str | None = None,
                          risk_score: float | None = None,
                          action_taken: str | None = None) -> None:
    """Store a captured packet to the DB for forensic inspection."""
    try:
        async with AsyncSessionLocal() as db:
            await crud.store_captured_packet(
                db,
                src_ip=payload.get("src_ip", ""),
                dst_ip=payload.get("dst_ip", ""),
                src_port=payload.get("src_port"),
                dst_port=payload.get("dst_port"),
                protocol=payload.get("protocol", "other"),
                pkt_len=payload.get("pkt_len"),
                flags=payload.get("flags"),
                is_syn=payload.get("is_syn", False),
                is_ack=payload.get("is_ack", False),
                is_rst=payload.get("is_rst", False),
                threat_type=threat_type,
                risk_score=risk_score,
                action_taken=action_taken,
            )
            await db.commit()
    except Exception as exc:
        log.debug("reporting_agent.packet_persist_failed", error=str(exc))


async def _handle_threat_packet_persist(payload: dict) -> None:
    """Persist every threat-flagged packet for inspection."""
    await _persist_packet(
        payload,
        threat_type=payload.get("threat_type"),
        risk_score=payload.get("risk_score"),
        action_taken=payload.get("action"),
    )


async def _handle_sample_normal_packet(payload: dict) -> None:
    """Sample 1 in 100 normal packets for baseline inspection."""
    global _packet_sample_counter
    _packet_sample_counter += 1
    if _packet_sample_counter % 100 == 0:
        await _persist_packet(payload)


event_bus.subscribe("report_event", _handle_report_event)
event_bus.subscribe("device_seen", _handle_device_seen_ws)
event_bus.subscribe("report_event", _handle_threat_packet_persist)
event_bus.subscribe("device_seen", _handle_sample_normal_packet)

