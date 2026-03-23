"""
Session logger for honeypot events (both SSH Cowrie and HTTP).
Persists sessions to DB and triggers GeoIP lookup.
"""
from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime

from app.core.logger import get_logger
from app.core.event_bus import publish
from app.database import crud
from app.database.session import AsyncSessionLocal
from app.websocket.live_updates import broadcast
from app.config import get_settings

log = get_logger("session_logger")
settings = get_settings()


def _normalize_timestamp(raw: str | None, fallback: datetime | None = None) -> datetime:
    if not raw:
        return fallback or datetime.utcnow()
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return fallback or datetime.utcnow()
    if parsed.tzinfo is not None:
        return parsed.astimezone().replace(tzinfo=None)
    return parsed


def _normalize_duration(value) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _describe_source(attacker_ip: str, geo: dict) -> tuple[dict, str, str]:
    normalized = dict(geo)
    try:
        ip = ipaddress.ip_address(attacker_ip)
    except ValueError:
        return normalized, "unresolved", "Approximate: unresolved"

    if attacker_ip.startswith("172.19."):
        normalized.setdefault("country", "Docker NAT")
        normalized.setdefault("org", "Docker bridge gateway")
        return (
            normalized,
            "docker_nat",
            "Docker NAT masked source; real LAN attacker IP is hidden by container networking",
        )

    if ip.is_private:
        normalized.setdefault("country", "Local network")
        normalized.setdefault("org", "Private subnet")
        return (
            normalized,
            "local_network",
            f"Private LAN source {attacker_ip}; exact geolocation is unavailable for internal addresses",
        )

    city = normalized.get("city")
    country = normalized.get("country")
    if city or country:
        return normalized, "approximate", f"Approximate: {city or country}"

    return normalized, "approximate", "Approximate: unresolved"


async def log_http_session(data: dict) -> None:
    """Persist an HTTP honeypot hit as a HoneypotSession."""
    await _save_session(
        honeypot_type="http",
        attacker_ip=data.get("attacker_ip", "unknown"),
        attacker_port=data.get("attacker_port"),
        session_id=str(uuid.uuid4()),
        started_at=datetime.utcnow(),
        commands_run=json.dumps({
            "method": data.get("method"),
            "path": data.get("path"),
            "body": data.get("body", ""),
        }),
    )


async def log_cowrie_session(cowrie_event: dict) -> None:
    """Parse a Cowrie JSON log entry and persist as a HoneypotSession."""
    attacker_ip = cowrie_event.get("src_ip", "unknown")
    await _save_session(
        honeypot_type="ssh",
        attacker_ip=attacker_ip,
        session_id=cowrie_event.get("session", str(uuid.uuid4())),
        started_at=_normalize_timestamp(cowrie_event.get("timestamp")),
        username_tried=cowrie_event.get("username"),
        password_tried=cowrie_event.get("password"),
        commands_run=json.dumps(cowrie_event.get("input", [])),
        duration_seconds=_normalize_duration(cowrie_event.get("duration")),
    )


async def _save_session(
    honeypot_type: str,
    attacker_ip: str,
    session_id: str,
    started_at: datetime,
    attacker_port: int | None = None,
    username_tried: str | None = None,
    password_tried: str | None = None,
    commands_run: str | None = None,
    duration_seconds: float | None = None,
) -> None:
    # GeoIP lookup
    geo = {}
    try:
        from app.geoip.geo_lookup import lookup
        geo = lookup(attacker_ip)
    except Exception:
        pass
    geo, location_accuracy, location_summary = _describe_source(attacker_ip, geo)

    try:
        created = False
        async with AsyncSessionLocal() as db:
            existing = await crud.get_honeypot_session_by_key(db, session_id)
            session = await crud.upsert_honeypot_session(
                db,
                session_id=session_id,
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                honeypot_type=honeypot_type,
                username_tried=username_tried,
                password_tried=password_tried,
                commands_run=commands_run,
                duration_seconds=duration_seconds,
                started_at=started_at,
                **geo,
            )
            created = existing is None
            await db.commit()
        if created:
            await publish("report_event", {
                "src_ip": attacker_ip,
                "dst_ip": settings.server_display_ip or None,
                "dst_port": settings.cowrie_redirect_port if honeypot_type == "ssh" else settings.http_honeypot_port,
                "protocol": "tcp",
                "threat_type": f"honeypot_{honeypot_type}",
                "risk_score": 0.98,
                "rule_score": 1.0,
                "ml_score": 0.0,
                "action": "honeypot",
                "country": session.country,
                "city": session.city,
                "asn": session.asn,
                "org": session.org,
                "latitude": session.latitude,
                "longitude": session.longitude,
                "timestamp": session.started_at.isoformat() if session.started_at else started_at.isoformat(),
                "incident_context": {
                    "source_tag": f"attacker::{attacker_ip.replace('.', '-')}",
                    "victim_ip": settings.server_display_ip or None,
                    "network_origin": "honeypot_direct",
                    "location_accuracy": location_accuracy,
                    "location_summary": location_summary,
                    "response_mode": "direct_honeypot_exposure",
                    "quarantine_target": True,
                    "target_hidden": True,
                    "honeypot_port": settings.cowrie_redirect_port if honeypot_type == "ssh" else settings.http_honeypot_port,
                    "tracked_commands": honeypot_type == "ssh",
                    "response_priority": "aggressive",
                },
                "incident_notes": json.dumps({
                    "source_tag": f"attacker::{attacker_ip.replace('.', '-')}",
                    "victim_ip": settings.server_display_ip or None,
                    "network_origin": "honeypot_direct",
                    "location_accuracy": location_accuracy,
                    "location_summary": location_summary,
                    "response_mode": "direct_honeypot_exposure",
                    "quarantine_target": True,
                    "target_hidden": True,
                    "honeypot_port": settings.cowrie_redirect_port if honeypot_type == "ssh" else settings.http_honeypot_port,
                    "tracked_commands": honeypot_type == "ssh",
                    "response_priority": "aggressive",
                }),
            })
        await broadcast({
            "type": "honeypot_session",
            "id": session.id,
            "session_id": session.session_id,
            "attacker_ip": session.attacker_ip,
            "attacker_port": session.attacker_port,
            "honeypot_type": session.honeypot_type,
            "username_tried": session.username_tried,
            "password_tried": session.password_tried,
            "commands_run": session.commands_run,
            "duration_seconds": session.duration_seconds,
            "country": session.country,
            "city": session.city,
            "asn": session.asn,
            "org": session.org,
            "latitude": session.latitude,
            "longitude": session.longitude,
            "started_at": session.started_at.isoformat() if session.started_at else started_at.isoformat(),
            "ended_at": session.ended_at.isoformat() if session.ended_at else None,
            "location_accuracy": location_accuracy,
            "location_summary": location_summary,
        })
        log.info("session_logger.saved", ip=attacker_ip, type=honeypot_type)
    except Exception as exc:
        log.error("session_logger.error", error=str(exc))
