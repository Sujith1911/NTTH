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
_live_device_flush_at: dict[str, float] = {}
_LIVE_DEVICE_FLUSH_SECONDS = 3.0
_SCANNER_PROBE_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 5985, 6379,
    8080, 8443, 8888, 9200, 27017,
}


def _is_scanner_probe_or_reply(payload: dict) -> bool:
    from app.config import get_settings

    settings = get_settings()
    server_ip = settings.server_display_ip
    src_ip = payload.get("src_ip", "")
    dst_ip = payload.get("dst_ip", "")
    src_port = payload.get("src_port")
    dst_port = payload.get("dst_port")
    if not server_ip or payload.get("protocol") != "tcp":
        return False
    if (
        src_ip == server_ip
        and is_managed_asset_ip(dst_ip)
        and dst_port in _SCANNER_PROBE_PORTS
    ):
        return True
    return bool(
        dst_ip == server_ip
        and is_managed_asset_ip(src_ip)
        and src_port in _SCANNER_PROBE_PORTS
        and isinstance(dst_port, int)
        and dst_port >= 1024
    )


def _should_persist_packet(payload: dict, *, threat: bool = False) -> bool:
    protocol = payload.get("protocol")
    src_ip = payload.get("src_ip", "")
    dst_ip = payload.get("dst_ip", "")
    if protocol == "arp_scan":
        return False
    if not src_ip or not dst_ip:
        return False
    if src_ip.endswith((".255", ".0")) or dst_ip.endswith((".255", ".0")):
        return False
    # Filter out scanner ARP probes (gateway/server sending ARP who-has to subnet)
    if protocol == "arp":
        from app.config import get_settings
        _settings = get_settings()
        if src_ip in {_settings.server_display_ip, _settings.gateway_ip}:
            return False
    if _is_scanner_probe_or_reply(payload):
        return False
    if threat:
        return True
    return is_managed_asset_ip(src_ip)


async def _handle_report_event(payload: dict) -> None:
    try:
        from app.config import get_settings
        settings = get_settings()
        incident_context = payload.get("incident_context", {})
        victim_ip = (
            incident_context.get("victim_ip")
            or payload.get("dst_ip")
            or payload.get("src_ip")
        )
        src_ip = payload.get("src_ip", "")
        try:
            from app.ids.risk_clearance import should_suppress
            if should_suppress(src_ip, payload.get("timestamp")):
                log.info("reporting_agent.risk_update_suppressed_after_clear", ip=src_ip)
                return
        except Exception:
            pass
        managed_asset_ip = None
        if isinstance(src_ip, str) and is_managed_asset_ip(src_ip):
            managed_asset_ip = src_ip
        elif isinstance(victim_ip, str) and is_managed_asset_ip(victim_ip):
            managed_asset_ip = victim_ip
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

        risk_score = float(payload.get("risk_score") or 0.0)
        if (
            risk_score >= settings.risk_block_threshold
            and payload.get("action") != "block"
            and managed_asset_ip == src_ip
            and src_ip not in {settings.gateway_ip, settings.server_display_ip}
        ):
            await event_bus.publish("enforcement_action", {
                **payload,
                "action": "block",
                "base_action": payload.get("action"),
                "incident_context": {
                    **incident_context,
                    "response_mode": "quarantine_source",
                    "decision_reason": (
                        f"risk_score={risk_score:.2f}; final_action=block; "
                        f"threshold={settings.risk_block_threshold:.2f}; source=reporting_agent"
                    ),
                },
            })

    except Exception as exc:
        log.error("reporting_agent.error", error=str(exc))


async def _handle_device_seen_ws(payload: dict) -> None:
    """Forward discovered/live devices to WS so UI screens update live."""
    import time

    src_ip = payload.get("src_ip")
    if not src_ip or not is_managed_asset_ip(src_ip):
        return

    now = time.monotonic()
    is_scan = payload.get("protocol") == "arp_scan"
    last_flush = _live_device_flush_at.get(src_ip, 0.0)
    if not is_scan and now - last_flush < _LIVE_DEVICE_FLUSH_SECONDS:
        return
    _live_device_flush_at[src_ip] = now

    from app.websocket.live_updates import broadcast
    try:
        async with AsyncSessionLocal() as db:
            await crud.upsert_device_details(
                db,
                src_ip,
                mac_address=payload.get("mac_address"),
                hostname=payload.get("hostname"),
                vendor=payload.get("vendor"),
                open_ports=payload.get("open_ports"),
            )
            await db.commit()

        await broadcast({
            "type": "device_seen",
            "ip": src_ip,
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
    if not _should_persist_packet(payload, threat=threat_type is not None):
        return
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
                payload_len=payload.get("payload_len"),
                direction=payload.get("direction"),
                src_mac=payload.get("src_mac"),
                dst_mac=payload.get("dst_mac"),
                ip_version=payload.get("ip_version"),
                ip_ttl=payload.get("ip_ttl"),
                ip_tos=payload.get("ip_tos"),
                ip_id=payload.get("ip_id"),
                ip_flags=payload.get("ip_flags"),
                frag_offset=payload.get("frag_offset"),
                flags=payload.get("flags"),
                tcp_seq=payload.get("tcp_seq"),
                tcp_ack=payload.get("tcp_ack"),
                tcp_window=payload.get("tcp_window"),
                tcp_options=payload.get("tcp_options"),
                udp_len=payload.get("udp_len"),
                icmp_type=payload.get("icmp_type"),
                icmp_code=payload.get("icmp_code"),
                payload_preview=payload.get("payload_preview"),
                payload_text=payload.get("payload_text"),
                http_method=payload.get("http_method"),
                http_host=payload.get("http_host"),
                http_path=payload.get("http_path"),
                http_user_agent=payload.get("http_user_agent"),
                http_content_type=payload.get("http_content_type"),
                http_body_preview=payload.get("http_body_preview"),
                http_form_fields=payload.get("http_form_fields"),
                tls_sni=payload.get("tls_sni"),
                tls_alpn=payload.get("tls_alpn"),
                tls_version=payload.get("tls_version"),
                tls_record_type=payload.get("tls_record_type"),
                quic_hint=payload.get("quic_hint", False),
                flow_id=payload.get("flow_id"),
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
    """Persist live packets so the inspector shows real traffic immediately."""
    global _packet_sample_counter
    _packet_sample_counter += 1
    await _persist_packet(payload)


event_bus.subscribe("report_event", _handle_report_event)
event_bus.subscribe("device_seen", _handle_device_seen_ws)
event_bus.subscribe("report_event", _handle_threat_packet_persist)
event_bus.subscribe("device_seen", _handle_sample_normal_packet)
