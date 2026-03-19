"""
Async CRUD operations for all ORM models.
These are thin data-access functions — business logic stays in agents/routes.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional, Sequence

from sqlalchemy import func, select, update
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


async def list_devices(db: AsyncSession, page: int = 1, page_size: int = 50) -> tuple[int, Sequence[Device]]:
    count_q = select(func.count()).select_from(Device)
    total = (await db.execute(count_q)).scalar_one()
    q = select(Device).offset((page - 1) * page_size).limit(page_size).order_by(Device.last_seen.desc())
    rows = (await db.execute(q)).scalars().all()
    return total, rows


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


async def list_honeypot_sessions(db: AsyncSession, page: int = 1, page_size: int = 50) -> tuple[int, Sequence[HoneypotSession]]:
    count_q = select(func.count()).select_from(HoneypotSession)
    total = (await db.execute(count_q)).scalar_one()
    q = select(HoneypotSession).order_by(HoneypotSession.started_at.desc()).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(q)).scalars().all()
    return total, rows


async def get_honeypot_session(db: AsyncSession, session_id: str) -> Optional[HoneypotSession]:
    result = await db.execute(select(HoneypotSession).where(HoneypotSession.id == session_id))
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
