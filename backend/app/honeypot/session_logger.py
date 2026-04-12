"""
Session logger for honeypot events (both SSH Cowrie and HTTP).
Persists sessions to DB and triggers GeoIP lookup.
"""
from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime
from typing import Any

from app.core.logger import get_logger
from app.core.event_bus import publish
from app.database import crud
from app.database.session import AsyncSessionLocal
from app.websocket.live_updates import broadcast
from app.config import get_settings

log = get_logger("session_logger")
settings = get_settings()
_REDIRECT_CONTEXT_TTL_SECONDS = 900
_recent_redirect_contexts: list[dict[str, Any]] = []


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


def register_redirect_context(
    *,
    attacker_ip: str,
    observed_attacker_ip: str,
    victim_ip: str | None,
    victim_port: int | None,
    honeypot_type: str,
    honeypot_port: int | None,
) -> None:
    now = datetime.utcnow()
    _recent_redirect_contexts.append({
        "attacker_ip": attacker_ip,
        "observed_attacker_ip": observed_attacker_ip,
        "victim_ip": victim_ip,
        "victim_port": victim_port,
        "honeypot_type": honeypot_type,
        "honeypot_port": honeypot_port,
        "created_at": now,
    })
    cutoff = now.timestamp() - _REDIRECT_CONTEXT_TTL_SECONDS
    _recent_redirect_contexts[:] = [
        item for item in _recent_redirect_contexts
        if item["created_at"].timestamp() >= cutoff
    ]


def _resolve_redirect_context(
    *,
    observed_attacker_ip: str,
    honeypot_type: str,
    started_at: datetime,
) -> tuple[str, str | None, int | None, bool, str | None]:
    cutoff = started_at.timestamp() - _REDIRECT_CONTEXT_TTL_SECONDS
    candidates = [
        item for item in _recent_redirect_contexts
        if item["honeypot_type"] == honeypot_type
        and item["created_at"].timestamp() >= cutoff
    ]
    if not candidates:
        return observed_attacker_ip, None, None, False, None

    exact = [item for item in candidates if item["attacker_ip"] == observed_attacker_ip]
    if exact:
        chosen = exact[-1]
        return (
            chosen["attacker_ip"],
            chosen["victim_ip"],
            chosen["victim_port"],
            False,
            None,
        )

    if observed_attacker_ip.startswith("172.19."):
        distinct_attackers = {item["attacker_ip"] for item in candidates}
        if len(distinct_attackers) == 1:
            chosen = candidates[-1]
            return (
                chosen["attacker_ip"],
                chosen["victim_ip"],
                chosen["victim_port"],
                True,
                f"Docker/NAT exposed {observed_attacker_ip} to Cowrie; original attacker IP was correlated from the redirect rule.",
            )
        return (
            observed_attacker_ip,
            None,
            None,
            True,
            f"Docker/NAT exposed {observed_attacker_ip} to Cowrie and multiple recent redirect candidates exist, so the original attacker could not be resolved safely.",
        )

    return observed_attacker_ip, None, None, False, None


async def log_http_session(data: dict) -> None:
    """Persist an HTTP honeypot hit as a HoneypotSession."""
    started_at = datetime.utcnow()
    observed_attacker_ip = data.get("attacker_ip", "unknown")
    attacker_ip, victim_ip, victim_port, source_masked, source_mask_reason = _resolve_redirect_context(
        observed_attacker_ip=observed_attacker_ip,
        honeypot_type="http",
        started_at=started_at,
    )
    await _save_session(
        honeypot_type="http",
        attacker_ip=attacker_ip,
        observed_attacker_ip=observed_attacker_ip,
        attacker_port=data.get("attacker_port"),
        session_id=str(uuid.uuid4()),
        started_at=started_at,
        victim_ip=victim_ip,
        victim_port=victim_port,
        commands_run=json.dumps({
            "method": data.get("method"),
            "path": data.get("path"),
            "body": data.get("body", ""),
        }),
        source_masked=source_masked,
        source_mask_reason=source_mask_reason,
    )


async def log_cowrie_session(cowrie_event: dict) -> None:
    """Parse a Cowrie JSON log entry and persist as a HoneypotSession."""
    started_at = _normalize_timestamp(cowrie_event.get("timestamp"))
    observed_attacker_ip = cowrie_event.get("src_ip", "unknown")
    attacker_ip, victim_ip, victim_port, source_masked, source_mask_reason = _resolve_redirect_context(
        observed_attacker_ip=observed_attacker_ip,
        honeypot_type="ssh",
        started_at=started_at,
    )
    await _save_session(
        honeypot_type="ssh",
        attacker_ip=attacker_ip,
        observed_attacker_ip=observed_attacker_ip,
        session_id=cowrie_event.get("session", str(uuid.uuid4())),
        started_at=started_at,
        username_tried=cowrie_event.get("username"),
        password_tried=cowrie_event.get("password"),
        commands_run=json.dumps(cowrie_event.get("input", [])),
        duration_seconds=_normalize_duration(cowrie_event.get("duration")),
        victim_ip=victim_ip,
        victim_port=victim_port,
        source_masked=source_masked,
        source_mask_reason=source_mask_reason,
    )


async def _save_session(
    honeypot_type: str,
    attacker_ip: str,
    observed_attacker_ip: str,
    session_id: str,
    started_at: datetime,
    attacker_port: int | None = None,
    victim_ip: str | None = None,
    victim_port: int | None = None,
    username_tried: str | None = None,
    password_tried: str | None = None,
    commands_run: str | None = None,
    duration_seconds: float | None = None,
    source_masked: bool = False,
    source_mask_reason: str | None = None,
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
                observed_attacker_ip=observed_attacker_ip,
                attacker_port=attacker_port,
                victim_ip=victim_ip,
                victim_port=victim_port,
                honeypot_type=honeypot_type,
                username_tried=username_tried,
                password_tried=password_tried,
                commands_run=commands_run,
                duration_seconds=duration_seconds,
                started_at=started_at,
                source_masked=source_masked,
                source_mask_reason=source_mask_reason,
                **geo,
            )
            created = existing is None
            await db.commit()
        if created:
            await publish("report_event", {
                "src_ip": attacker_ip,
                "dst_ip": victim_ip or settings.server_display_ip or None,
                "dst_port": victim_port or (22 if honeypot_type == "ssh" else 80),
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
                    "victim_ip": victim_ip or settings.server_display_ip or None,
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
                    "victim_ip": victim_ip or settings.server_display_ip or None,
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
            "observed_attacker_ip": session.observed_attacker_ip,
            "attacker_port": session.attacker_port,
            "victim_ip": session.victim_ip,
            "victim_port": session.victim_port,
            "honeypot_type": session.honeypot_type,
            "username_tried": session.username_tried,
            "password_tried": session.password_tried,
            "commands_run": session.commands_run,
            "duration_seconds": session.duration_seconds,
            "source_masked": session.source_masked,
            "source_mask_reason": session.source_mask_reason,
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
