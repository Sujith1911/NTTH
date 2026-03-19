"""
Session logger for honeypot events (both SSH Cowrie and HTTP).
Persists sessions to DB and triggers GeoIP lookup.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime

from app.core.logger import get_logger
from app.database import crud
from app.database.session import AsyncSessionLocal

log = get_logger("session_logger")


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
        started_at=datetime.fromisoformat(cowrie_event.get("timestamp", datetime.utcnow().isoformat())),
        username_tried=cowrie_event.get("username"),
        password_tried=cowrie_event.get("password"),
        commands_run=json.dumps(cowrie_event.get("input", [])),
        duration_seconds=cowrie_event.get("duration"),
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

    try:
        async with AsyncSessionLocal() as db:
            await crud.create_honeypot_session(
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
            await db.commit()
        log.info("session_logger.saved", ip=attacker_ip, type=honeypot_type)
    except Exception as exc:
        log.error("session_logger.error", error=str(exc))
