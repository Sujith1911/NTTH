"""
Async CRUD operations for all ORM models.
These are thin data-access functions — business logic stays in agents/routes.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Optional, Sequence

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import (
    Device, DeviceStat, FirewallRule, HoneypotSession,
    SystemLog, ThreatEvent, User,
)


# ── Users ─────────────────────────────────────────────────────────────────────

async def get_user_by_username(db: AsyncSession, username: str) -> Optional[User]:
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: str) -> Optional[User]:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def create_user(db: AsyncSession, username: str, hashed_password: str, role: str = "user") -> User:
    user = User(username=username, hashed_password=hashed_password, role=role)
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


async def update_last_login(db: AsyncSession, user_id: str) -> None:
    await db.execute(
        update(User).where(User.id == user_id).values(last_login=datetime.utcnow())
    )


# ── Devices ───────────────────────────────────────────────────────────────────

async def get_or_create_device(db: AsyncSession, ip_address: str) -> tuple[Device, bool]:
    """Return (device, created). Updates last_seen on each call."""
    result = await db.execute(select(Device).where(Device.ip_address == ip_address))
    device = result.scalar_one_or_none()
    if device:
        device.last_seen = datetime.utcnow()
        return device, False
    device = Device(ip_address=ip_address)
    db.add(device)
    await db.flush()
    await db.refresh(device)
    return device, True


async def upsert_device_details(
    db: AsyncSession,
    ip_address: str,
    *,
    mac_address: Optional[str] = None,
    hostname: Optional[str] = None,
    vendor: Optional[str] = None,
    risk_score: Optional[float] = None,
) -> tuple[Device, bool]:
    """Create or update a device row with the latest discovered metadata."""
    device, created = await get_or_create_device(db, ip_address)
    device.last_seen = datetime.utcnow()
    if mac_address:
        device.mac_address = mac_address
    if hostname:
        device.hostname = hostname
    if vendor:
        device.vendor = vendor
    if risk_score is not None:
        device.risk_score = risk_score
    return device, created


async def list_devices(db: AsyncSession, page: int = 1, page_size: int = 50) -> tuple[int, Sequence[Device]]:
    count_q = select(func.count()).select_from(Device)
    total = (await db.execute(count_q)).scalar_one()
    q = select(Device).offset((page - 1) * page_size).limit(page_size).order_by(Device.last_seen.desc())
    rows = (await db.execute(q)).scalars().all()
    return total, rows


async def get_device_by_ip(db: AsyncSession, ip_address: str) -> Optional[Device]:
    result = await db.execute(select(Device).where(Device.ip_address == ip_address))
    return result.scalar_one_or_none()


async def get_device(db: AsyncSession, device_id: str) -> Optional[Device]:
    result = await db.execute(select(Device).where(Device.id == device_id))
    return result.scalar_one_or_none()


async def update_device_risk(db: AsyncSession, device_id: str, risk_score: float) -> None:
    await db.execute(
        update(Device).where(Device.id == device_id).values(risk_score=risk_score)
    )


async def update_device_trust(db: AsyncSession, device_id: str, is_trusted: bool) -> Optional[Device]:
    """Toggle trust status on a device. Returns updated device or None if not found."""
    result = await db.execute(select(Device).where(Device.id == device_id))
    device = result.scalar_one_or_none()
    if device:
        device.is_trusted = is_trusted
    return device


async def add_device_stat(db: AsyncSession, stat: DeviceStat) -> None:
    db.add(stat)
    await db.flush()


async def list_device_stats(
    db: AsyncSession, device_id: str, page: int = 1, page_size: int = 50
) -> tuple[int, Sequence[DeviceStat]]:
    """Return paginated DeviceStat records for a specific device."""
    count_q = select(func.count()).select_from(DeviceStat).where(DeviceStat.device_id == device_id)
    total = (await db.execute(count_q)).scalar_one()
    q = (
        select(DeviceStat)
        .where(DeviceStat.device_id == device_id)
        .order_by(DeviceStat.recorded_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await db.execute(q)).scalars().all()
    return total, rows


# ── Threat Events ─────────────────────────────────────────────────────────────

async def create_threat_event(db: AsyncSession, **kwargs) -> ThreatEvent:
    event = ThreatEvent(**kwargs)
    db.add(event)
    await db.flush()
    await db.refresh(event)
    return event


async def list_threats(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 50,
    unacknowledged_only: bool = False,
) -> tuple[int, Sequence[ThreatEvent]]:
    q = select(ThreatEvent)
    if unacknowledged_only:
        q = q.where(ThreatEvent.acknowledged == False)  # noqa: E712
    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()
    q = q.order_by(ThreatEvent.detected_at.desc()).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(q)).scalars().all()
    return total, rows


async def acknowledge_threat(db: AsyncSession, threat_id: str, username: str, notes: Optional[str]) -> Optional[ThreatEvent]:
    result = await db.execute(select(ThreatEvent).where(ThreatEvent.id == threat_id))
    event = result.scalar_one_or_none()
    if event:
        event.acknowledged = True
        event.acknowledged_by = username
        if notes:
            event.notes = notes
    return event


# ── Honeypot Sessions ─────────────────────────────────────────────────────────

async def create_honeypot_session(db: AsyncSession, **kwargs) -> HoneypotSession:
    session = HoneypotSession(**kwargs)
    db.add(session)
    await db.flush()
    await db.refresh(session)
    return session


async def upsert_honeypot_session(
    db: AsyncSession,
    *,
    session_id: str,
    attacker_ip: str,
    observed_attacker_ip: Optional[str] = None,
    honeypot_type: str,
    started_at: datetime,
    attacker_port: Optional[int] = None,
    victim_ip: Optional[str] = None,
    victim_port: Optional[int] = None,
    username_tried: Optional[str] = None,
    password_tried: Optional[str] = None,
    commands_run: Optional[str] = None,
    duration_seconds: Optional[float] = None,
    ended_at: Optional[datetime] = None,
    source_masked: bool = False,
    source_mask_reason: Optional[str] = None,
    **geo,
) -> HoneypotSession:
    result = await db.execute(select(HoneypotSession).where(HoneypotSession.session_id == session_id))
    session = result.scalar_one_or_none()
    if not session:
        session = HoneypotSession(
            session_id=session_id,
            attacker_ip=attacker_ip,
            observed_attacker_ip=observed_attacker_ip,
            honeypot_type=honeypot_type,
            started_at=started_at,
        )
        db.add(session)

    session.attacker_ip = attacker_ip
    session.observed_attacker_ip = observed_attacker_ip or session.observed_attacker_ip
    session.honeypot_type = honeypot_type
    session.started_at = min(session.started_at, started_at) if session.started_at else started_at
    session.attacker_port = attacker_port or session.attacker_port
    session.victim_ip = victim_ip or session.victim_ip
    session.victim_port = victim_port or session.victim_port
    session.username_tried = username_tried or session.username_tried
    session.password_tried = password_tried or session.password_tried
    session.duration_seconds = duration_seconds or session.duration_seconds
    session.ended_at = ended_at or session.ended_at
    session.source_masked = source_masked or session.source_masked
    session.source_mask_reason = source_mask_reason or session.source_mask_reason

    if commands_run:
        try:
            existing = json.loads(session.commands_run) if session.commands_run else []
        except Exception:
            existing = [session.commands_run] if session.commands_run else []
        try:
            incoming = json.loads(commands_run)
        except Exception:
            incoming = [commands_run]
        if not isinstance(existing, list):
            existing = [existing]
        if not isinstance(incoming, list):
            incoming = [incoming]
        merged = existing + [item for item in incoming if item not in existing]
        session.commands_run = json.dumps(merged)
    elif commands_run is not None and not session.commands_run:
        session.commands_run = commands_run

    for field in ("country", "city", "asn", "org", "latitude", "longitude"):
        value = geo.get(field)
        if value is not None:
            setattr(session, field, value)

    await db.flush()
    await db.refresh(session)
    return session


async def list_honeypot_sessions(db: AsyncSession, page: int = 1, page_size: int = 50) -> tuple[int, Sequence[HoneypotSession]]:
    count_q = select(func.count()).select_from(HoneypotSession)
    total = (await db.execute(count_q)).scalar_one()
    q = select(HoneypotSession).order_by(HoneypotSession.started_at.desc()).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(q)).scalars().all()
    return total, rows


async def get_honeypot_session(db: AsyncSession, session_id: str) -> Optional[HoneypotSession]:
    result = await db.execute(select(HoneypotSession).where(HoneypotSession.id == session_id))
    return result.scalar_one_or_none()


async def get_honeypot_session_by_key(db: AsyncSession, session_id: str) -> Optional[HoneypotSession]:
    result = await db.execute(select(HoneypotSession).where(HoneypotSession.session_id == session_id))
    return result.scalar_one_or_none()


# ── Firewall Rules ────────────────────────────────────────────────────────────

async def create_firewall_rule(db: AsyncSession, **kwargs) -> FirewallRule:
    rule = FirewallRule(**kwargs)
    db.add(rule)
    await db.flush()
    await db.refresh(rule)
    return rule


async def list_active_firewall_rules(db: AsyncSession) -> Sequence[FirewallRule]:
    result = await db.execute(select(FirewallRule).where(FirewallRule.is_active == True))  # noqa: E712
    return result.scalars().all()


async def deactivate_firewall_rule(db: AsyncSession, rule_id: str) -> Optional[FirewallRule]:
    result = await db.execute(select(FirewallRule).where(FirewallRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if rule:
        rule.is_active = False
        rule.removed_at = datetime.utcnow()
    return rule


async def deactivate_all_firewall_rules(db: AsyncSession) -> int:
    result = await db.execute(select(FirewallRule).where(FirewallRule.is_active == True))  # noqa: E712
    rules = result.scalars().all()
    now = datetime.utcnow()
    for rule in rules:
        rule.is_active = False
        rule.removed_at = now
    return len(rules)


async def get_expired_firewall_rules(db: AsyncSession) -> Sequence[FirewallRule]:
    now = datetime.utcnow()
    result = await db.execute(
        select(FirewallRule).where(
            FirewallRule.is_active == True,  # noqa: E712
            FirewallRule.expires_at != None,  # noqa: E711
            FirewallRule.expires_at <= now,
        )
    )
    return result.scalars().all()


async def rule_exists_for_ip(db: AsyncSession, target_ip: str, rule_type: str) -> bool:
    result = await db.execute(
        select(FirewallRule).where(
            FirewallRule.target_ip == target_ip,
            FirewallRule.rule_type == rule_type,
            FirewallRule.is_active == True,  # noqa: E712
        )
    )
    return result.scalar_one_or_none() is not None


async def rule_exists(
    db: AsyncSession,
    *,
    target_ip: str,
    rule_type: str,
    match_dst_ip: Optional[str] = None,
    match_dst_port: Optional[int] = None,
) -> bool:
    query = select(FirewallRule).where(
        FirewallRule.target_ip == target_ip,
        FirewallRule.rule_type == rule_type,
        FirewallRule.is_active == True,  # noqa: E712
    )
    if match_dst_ip is not None:
        query = query.where(FirewallRule.match_dst_ip == match_dst_ip)
    if match_dst_port is not None:
        query = query.where(FirewallRule.match_dst_port == match_dst_port)
    result = await db.execute(query)
    return result.scalar_one_or_none() is not None


# ── System Logs ───────────────────────────────────────────────────────────────

async def create_system_log(db: AsyncSession, level: str, component: str, message: str, extra: Optional[str] = None) -> None:
    log = SystemLog(level=level, component=component, message=message, extra=extra)
    db.add(log)
    await db.flush()


async def list_system_logs(db: AsyncSession, page: int = 1, page_size: int = 100) -> tuple[int, Sequence[SystemLog]]:
    count_q = select(func.count()).select_from(SystemLog)
    total = (await db.execute(count_q)).scalar_one()
    q = select(SystemLog).order_by(SystemLog.logged_at.desc()).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(q)).scalars().all()
    return total, rows


# ── Users (admin) ──────────────────────────────────────────────────────────────

async def list_users(db: AsyncSession) -> Sequence[User]:
    result = await db.execute(select(User).order_by(User.created_at.asc()))
    return result.scalars().all()


async def deactivate_user(db: AsyncSession, username: str) -> Optional[User]:
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user:
        user.is_active = False
    return user


# ── Firewall (all rules, paginated) ──────────────────────────────────────────────────

async def list_all_firewall_rules(
    db: AsyncSession, page: int = 1, page_size: int = 50
) -> tuple[int, Sequence[FirewallRule]]:
    """All rules (active and expired) ordered by creation time desc."""
    count_q = select(func.count()).select_from(FirewallRule)
    total = (await db.execute(count_q)).scalar_one()
    q = (
        select(FirewallRule)
        .order_by(FirewallRule.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await db.execute(q)).scalars().all()
    return total, rows


# ── Dashboard + Threat Stats ────────────────────────────────────────────────────────

async def get_dashboard_stats(db: AsyncSession) -> dict:
    """Return aggregate counts for the dashboard."""
    total_devices = (await db.execute(select(func.count()).select_from(Device))).scalar_one()
    total_threats = (await db.execute(select(func.count()).select_from(ThreatEvent))).scalar_one()
    active_rules = (
        await db.execute(
            select(func.count()).select_from(FirewallRule).where(FirewallRule.is_active == True)  # noqa: E712
        )
    ).scalar_one()
    total_sessions = (await db.execute(select(func.count()).select_from(HoneypotSession))).scalar_one()
    unacknowledged = (
        await db.execute(
            select(func.count()).select_from(ThreatEvent).where(ThreatEvent.acknowledged == False)  # noqa: E712
        )
    ).scalar_one()
    high_risk = (
        await db.execute(
            select(func.count()).select_from(ThreatEvent).where(ThreatEvent.risk_score >= 0.9)
        )
    ).scalar_one()
    return {
        "total_devices": total_devices,
        "total_threats": total_threats,
        "active_firewall_rules": active_rules,
        "total_honeypot_sessions": total_sessions,
        "unacknowledged_threats": unacknowledged,
        "high_risk_threats": high_risk,
    }


async def get_threat_stats(db: AsyncSession) -> dict:
    """Return threat counts grouped by type and action_taken."""
    total = (await db.execute(select(func.count()).select_from(ThreatEvent))).scalar_one()

    type_rows = (
        await db.execute(
            select(ThreatEvent.threat_type, func.count().label("count"))
            .group_by(ThreatEvent.threat_type)
            .order_by(func.count().desc())
        )
    ).all()

    action_rows = (
        await db.execute(
            select(ThreatEvent.action_taken, func.count().label("count"))
            .group_by(ThreatEvent.action_taken)
            .order_by(func.count().desc())
        )
    ).all()

    return {
        "total": total,
        "by_type": [{"threat_type": r[0], "count": r[1]} for r in type_rows],
        "by_action": [{"action_taken": r[0], "count": r[1]} for r in action_rows],
    }


async def get_containment_summary(db: AsyncSession) -> dict:
    """Return attempted responder actions alongside currently enforced rules."""
    attempted_rows = (
        await db.execute(
            select(ThreatEvent.action_taken, func.count().label("count"))
            .where(ThreatEvent.action_taken.is_not(None))
            .group_by(ThreatEvent.action_taken)
        )
    ).all()
    active_rows = (
        await db.execute(
            select(FirewallRule.rule_type, func.count().label("count"))
            .where(FirewallRule.is_active == True)  # noqa: E712
            .group_by(FirewallRule.rule_type)
        )
    ).all()

    attempted = {row[0]: row[1] for row in attempted_rows if row[0]}
    active = {row[0]: row[1] for row in active_rows if row[0]}
    return {
        "attempted": {
            "block": attempted.get("block", 0),
            "honeypot": attempted.get("honeypot", 0),
            "rate_limit": attempted.get("rate_limit", 0),
            "log": attempted.get("log", 0),
        },
        "active": {
            "block": active.get("block", 0),
            "redirect": active.get("redirect", 0),
            "rate_limit": active.get("rate_limit", 0),
        },
        "attempted_total": sum(attempted.values()),
        "active_total": sum(active.values()),
    }


async def purge_devices_outside_subnet(db: AsyncSession, subnet: str) -> int:
    from ipaddress import ip_address, ip_network

    try:
        network = ip_network(subnet, strict=False)
    except ValueError:
        return 0

    result = await db.execute(select(Device.id, Device.ip_address))
    stale_ids: list[str] = []
    for device_id, ip in result.all():
        try:
            if ip_address(ip) not in network:
                stale_ids.append(device_id)
        except ValueError:
            stale_ids.append(device_id)

    if not stale_ids:
        return 0

    await db.execute(
        update(ThreatEvent)
        .where(ThreatEvent.device_id.in_(stale_ids))
        .values(device_id=None)
    )
    await db.execute(delete(DeviceStat).where(DeviceStat.device_id.in_(stale_ids)))
    await db.execute(delete(Device).where(Device.id.in_(stale_ids)))
    return len(stale_ids)
