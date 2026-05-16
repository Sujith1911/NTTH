"""
Async CRUD operations for all ORM models.
These are thin data-access functions — business logic stays in agents/routes.
"""
from __future__ import annotations

import json
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Optional, Sequence

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time_utils import utc_now_naive
from app.database.models import (
    CapturedPacket, Device, DeviceStat, FirewallRule, HoneypotSession,
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
        update(User).where(User.id == user_id).values(last_login=utc_now_naive())
    )


# ── Devices ───────────────────────────────────────────────────────────────────

async def get_or_create_device(db: AsyncSession, ip_address: str) -> tuple[Device, bool]:
    """Return (device, created). Updates last_seen on each call."""
    result = await db.execute(select(Device).where(Device.ip_address == ip_address))
    device = result.scalar_one_or_none()
    if device:
        device.last_seen = utc_now_naive()
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
    open_ports: Optional[list[int]] = None,
) -> tuple[Device, bool]:
    """Create or update a device row with the latest discovered metadata."""
    import json
    device, created = await get_or_create_device(db, ip_address)
    device.last_seen = utc_now_naive()
    if mac_address:
        device.mac_address = mac_address
    if hostname:
        device.hostname = hostname
    if vendor:
        device.vendor = vendor
    if risk_score is not None:
        device.risk_score = risk_score
    if open_ports is not None:
        device.open_ports = json.dumps(open_ports)
    return device, created


async def list_devices(db: AsyncSession, page: int = 1, page_size: int = 50) -> tuple[int, Sequence[Device]]:
    valid_host_filters = (
        ~Device.ip_address.like("%.255"),
        ~Device.ip_address.like("%.0"),
        ~Device.ip_address.like("224.%"),
        ~Device.ip_address.like("239.%"),
        ~Device.ip_address.like("127.%"),
    )
    count_q = select(func.count()).select_from(Device).where(*valid_host_filters)
    total = (await db.execute(count_q)).scalar_one()
    q = (
        select(Device)
        .where(*valid_host_filters)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .order_by(Device.last_seen.desc())
    )
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
        rule.removed_at = utc_now_naive()
    return rule


async def deactivate_all_firewall_rules(db: AsyncSession) -> int:
    result = await db.execute(select(FirewallRule).where(FirewallRule.is_active == True))  # noqa: E712
    rules = result.scalars().all()
    now = utc_now_naive()
    for rule in rules:
        rule.is_active = False
        rule.removed_at = now
    return len(rules)


async def deactivate_firewall_rules_for_ip(db: AsyncSession, target_ip: str) -> int:
    """Mark every active firewall rule for an IP inactive."""
    result = await db.execute(
        select(FirewallRule).where(
            FirewallRule.target_ip == target_ip,
            FirewallRule.is_active == True,  # noqa: E712
        )
    )
    rules = result.scalars().all()
    now = utc_now_naive()
    for rule in rules:
        rule.is_active = False
        rule.removed_at = now
    return len(rules)


async def get_expired_firewall_rules(db: AsyncSession) -> Sequence[FirewallRule]:
    now = utc_now_naive()
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


async def purge_invalid_devices(db: AsyncSession, subnet: Optional[str] = None) -> int:
    """Remove broadcast/network/multicast device rows that cannot be real hosts."""
    network = None
    if subnet:
        try:
            network = ip_network(subnet, strict=False)
        except ValueError:
            network = None

    result = await db.execute(select(Device.id, Device.ip_address))
    invalid_ids: list[str] = []
    for device_id, ip in result.all():
        try:
            parsed = ip_address(ip)
            invalid = (
                parsed.is_multicast
                or parsed.is_unspecified
                or parsed.is_loopback
                or str(parsed).endswith(".255")
                or str(parsed).endswith(".0")
            )
            if network is not None:
                invalid = invalid or parsed == network.network_address or parsed == network.broadcast_address
            if invalid:
                invalid_ids.append(device_id)
        except ValueError:
            invalid_ids.append(device_id)

    if not invalid_ids:
        return 0

    await db.execute(
        update(ThreatEvent)
        .where(ThreatEvent.device_id.in_(invalid_ids))
        .values(device_id=None)
    )
    await db.execute(delete(DeviceStat).where(DeviceStat.device_id.in_(invalid_ids)))
    await db.execute(delete(Device).where(Device.id.in_(invalid_ids)))
    return len(invalid_ids)


async def purge_unseen_devices_in_subnet(
    db: AsyncSession,
    subnet: str,
    live_ips: set[str],
    preserve_ips: set[str] | None = None,
) -> int:
    """Remove stale non-live device rows from the scanned subnet."""
    try:
        network = ip_network(subnet, strict=False)
    except ValueError:
        return 0

    preserve = preserve_ips or set()
    result = await db.execute(select(Device.id, Device.ip_address, Device.is_trusted))
    stale_ids: list[str] = []
    for device_id, ip, is_trusted in result.all():
        if ip in live_ips or ip in preserve or is_trusted:
            continue
        try:
            parsed = ip_address(ip)
            if parsed in network:
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


# ── Captured Packets ──────────────────────────────────────────────────────────

async def store_captured_packet(db: AsyncSession, **kwargs) -> CapturedPacket:
    """Persist a captured packet for forensic inspection."""
    pkt = CapturedPacket(**kwargs)
    db.add(pkt)
    await db.flush()
    return pkt


async def list_captured_packets(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 100,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    service_ports: Optional[Sequence[int]] = None,
    direction: Optional[str] = None,
    threat_type: Optional[str] = None,
    captured_from: Optional[datetime] = None,
    captured_to: Optional[datetime] = None,
    only_threats: bool = False,
) -> tuple[int, Sequence[CapturedPacket]]:
    """List captured packets with optional filters for inspection."""
    q = select(CapturedPacket)
    if src_ip:
        q = q.where(CapturedPacket.src_ip == src_ip)
    if dst_ip:
        q = q.where(CapturedPacket.dst_ip == dst_ip)
    if protocol:
        q = q.where(CapturedPacket.protocol == protocol)
    if service_ports:
        q = q.where(
            (CapturedPacket.src_port.in_(service_ports))
            | (CapturedPacket.dst_port.in_(service_ports))
        )
    if direction:
        q = q.where(CapturedPacket.direction == direction)
    if threat_type:
        q = q.where(CapturedPacket.threat_type == threat_type)
    if captured_from:
        q = q.where(CapturedPacket.captured_at >= captured_from)
    if captured_to:
        q = q.where(CapturedPacket.captured_at <= captured_to)
    if only_threats:
        q = q.where(CapturedPacket.threat_type.isnot(None))

    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()
    q = q.order_by(CapturedPacket.captured_at.desc()).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(q)).scalars().all()
    return total, rows


async def get_captured_packet(db: AsyncSession, packet_id: int) -> Optional[CapturedPacket]:
    return await db.get(CapturedPacket, packet_id)


async def delete_captured_packet(db: AsyncSession, packet_id: int) -> bool:
    result = await db.execute(delete(CapturedPacket).where(CapturedPacket.id == packet_id))
    return bool(result.rowcount)


async def delete_captured_packets(
    db: AsyncSession,
    *,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    service_ports: Optional[Sequence[int]] = None,
    direction: Optional[str] = None,
    threat_type: Optional[str] = None,
    captured_from: Optional[datetime] = None,
    captured_to: Optional[datetime] = None,
    only_threats: bool = False,
) -> int:
    q = delete(CapturedPacket)
    if src_ip:
        q = q.where(CapturedPacket.src_ip == src_ip)
    if dst_ip:
        q = q.where(CapturedPacket.dst_ip == dst_ip)
    if protocol:
        q = q.where(CapturedPacket.protocol == protocol)
    if service_ports:
        q = q.where(
            (CapturedPacket.src_port.in_(service_ports))
            | (CapturedPacket.dst_port.in_(service_ports))
        )
    if direction:
        q = q.where(CapturedPacket.direction == direction)
    if threat_type:
        q = q.where(CapturedPacket.threat_type == threat_type)
    if captured_from:
        q = q.where(CapturedPacket.captured_at >= captured_from)
    if captured_to:
        q = q.where(CapturedPacket.captured_at <= captured_to)
    if only_threats:
        q = q.where(CapturedPacket.threat_type.isnot(None))
    result = await db.execute(q)
    return int(result.rowcount or 0)


async def latest_threat_events_for_ips(
    db: AsyncSession,
    ips: Sequence[str],
    limit_per_ip: int = 5,
) -> dict[str, list[ThreatEvent]]:
    if not ips:
        return {}
    result = await db.execute(
        select(ThreatEvent)
        .where(ThreatEvent.src_ip.in_(ips))
        .order_by(ThreatEvent.src_ip.asc(), ThreatEvent.detected_at.desc())
    )
    grouped: dict[str, list[ThreatEvent]] = {ip: [] for ip in ips}
    for event in result.scalars().all():
        bucket = grouped.setdefault(event.src_ip, [])
        if len(bucket) < limit_per_ip:
            bucket.append(event)
    return grouped


async def purge_packet_noise(db: AsyncSession) -> int:
    """Remove synthetic scan packets and impossible broadcast rows from packet history."""
    result = await db.execute(
        delete(CapturedPacket).where(
            (CapturedPacket.protocol == "arp_scan")
            | CapturedPacket.src_ip.like("%.255")
            | CapturedPacket.dst_ip.like("%.255")
            | CapturedPacket.src_ip.like("%.0")
            | CapturedPacket.dst_ip.like("%.0")
        )
    )
    return int(result.rowcount or 0)


async def purge_synthetic_demo_data(db: AsyncSession) -> dict[str, int]:
    """Remove rows produced by bundled demo/simulation helpers."""
    demo_ips = {
        "1.2.3.4",
        "5.6.7.8",
        "10.142.204.55",
        "10.142.204.88",
        "45.33.32.156",
        "91.108.56.100",
        "103.203.57.12",
        "185.220.101.42",
        "185.220.101.50",
        "198.51.100.25",
    }
    demo_victims = {"10.142.204.241", "192.168.1.1"}
    packet_result = await db.execute(
        delete(CapturedPacket).where(
            CapturedPacket.src_ip.in_(demo_ips)
            | CapturedPacket.dst_ip.in_(demo_ips)
            | CapturedPacket.dst_ip.in_(demo_victims)
        )
    )
    threat_result = await db.execute(
        delete(ThreatEvent).where(
            ThreatEvent.src_ip.in_(demo_ips)
            | ThreatEvent.dst_ip.in_(demo_ips)
            | ThreatEvent.dst_ip.in_(demo_victims)
        )
    )
    rule_result = await db.execute(delete(FirewallRule).where(FirewallRule.target_ip.in_(demo_ips)))
    session_result = await db.execute(delete(HoneypotSession).where(HoneypotSession.attacker_ip.in_(demo_ips)))
    return {
        "packets": int(packet_result.rowcount or 0),
        "threats": int(threat_result.rowcount or 0),
        "rules": int(rule_result.rowcount or 0),
        "sessions": int(session_result.rowcount or 0),
    }


async def purge_benign_web_false_positives(db: AsyncSession) -> dict[str, int]:
    """Clear low-risk common web/DNS/VPN flows that were over-classified."""
    common_ports = {
        53, 80, 123, 443, 500, 853, 8080, 8443, 8888, 4500,
        5222, 5223, 5228, 5229, 5230,
    }
    packet_result = await db.execute(
        update(CapturedPacket)
        .where(
            CapturedPacket.threat_type == "suspicious",
            CapturedPacket.risk_score <= 0.5,
            (
                CapturedPacket.src_port.in_(common_ports)
                | CapturedPacket.dst_port.in_(common_ports)
            ),
        )
        .values(threat_type=None, risk_score=None, action_taken=None)
    )
    threat_result = await db.execute(
        delete(ThreatEvent).where(
            ThreatEvent.threat_type == "suspicious",
            ThreatEvent.risk_score <= 0.5,
            (
                ThreatEvent.dst_port.in_(common_ports)
            ),
        )
    )
    return {
        "packets": int(packet_result.rowcount or 0),
        "threats": int(threat_result.rowcount or 0),
    }


async def purge_scanner_false_positive_for_ip(
    db: AsyncSession,
    *,
    device_ip: str,
    server_ip: str,
) -> dict[str, int]:
    """Clear false positives caused by our own TCP connect scan replies."""
    scanner_ports = {
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 5985, 6379,
        8080, 8443, 8888, 9200, 27017,
    }
    packets = await db.execute(
        delete(CapturedPacket).where(
            (
                (CapturedPacket.src_ip == server_ip)
                & (CapturedPacket.dst_ip == device_ip)
                & CapturedPacket.dst_port.in_(scanner_ports)
            )
            | (
                (CapturedPacket.src_ip == device_ip)
                & (CapturedPacket.dst_ip == server_ip)
                & CapturedPacket.src_port.in_(scanner_ports)
            )
        )
    )
    threats = await db.execute(
        delete(ThreatEvent).where(
            ThreatEvent.src_ip == device_ip,
            ThreatEvent.dst_ip == server_ip,
        )
    )
    rules = await deactivate_firewall_rules_for_ip(db, device_ip)
    device = await get_device_by_ip(db, device_ip)
    if device:
        device.risk_score = 0.0
    return {
        "packets": int(packets.rowcount or 0),
        "threats": int(threats.rowcount or 0),
        "rules": rules,
        "devices": 1 if device else 0,
    }


async def purge_low_risk_normal_events_for_ip(db: AsyncSession, ip: str) -> dict[str, int]:
    """Delete old ML-noise 'normal' events that should not have become incidents."""
    threats = await db.execute(
        delete(ThreatEvent).where(
            (ThreatEvent.src_ip == ip) | (ThreatEvent.dst_ip == ip),
            ThreatEvent.threat_type == "normal",
            ThreatEvent.risk_score <= 0.3,
        )
    )
    packets = await db.execute(
        delete(CapturedPacket).where(
            (CapturedPacket.src_ip == ip) | (CapturedPacket.dst_ip == ip),
            CapturedPacket.threat_type == "normal",
            CapturedPacket.risk_score <= 0.3,
        )
    )
    return {
        "threats": int(threats.rowcount or 0),
        "packets": int(packets.rowcount or 0),
    }


async def purge_lan_broadcast_events_for_ip(db: AsyncSession, ip: str) -> dict[str, int]:
    """Delete broadcast/multicast LAN chatter that is not an attack."""
    threats = await db.execute(
        delete(ThreatEvent).where(
            ThreatEvent.src_ip == ip,
            (
                ThreatEvent.dst_ip.like("224.%")
                | ThreatEvent.dst_ip.like("239.%")
                | ThreatEvent.dst_ip.like("%.255")
            ),
            ThreatEvent.risk_score <= 0.4,
        )
    )
    packets = await db.execute(
        delete(CapturedPacket).where(
            CapturedPacket.src_ip == ip,
            (
                CapturedPacket.dst_ip.like("224.%")
                | CapturedPacket.dst_ip.like("239.%")
                | CapturedPacket.dst_ip.like("%.255")
            ),
        )
    )
    return {
        "threats": int(threats.rowcount or 0),
        "packets": int(packets.rowcount or 0),
    }


async def purge_scanner_false_positives(
    db: AsyncSession,
    *,
    server_ip: str,
    subnet: Optional[str] = None,
) -> dict[str, int]:
    """Clear false positives for all devices caused by our own port scanner."""
    if not server_ip:
        return {"packets": 0, "threats": 0, "rules": 0, "devices": 0}

    scanner_ports = {
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 5985, 6379,
        8080, 8443, 8888, 9200, 27017,
    }
    network = None
    if subnet:
        try:
            network = ip_network(subnet, strict=False)
        except ValueError:
            network = None

    result = await db.execute(select(Device.id, Device.ip_address))
    affected_ips: set[str] = set()
    affected_ids: list[str] = []
    for device_id, ip in result.all():
        if ip == server_ip:
            continue
        try:
            parsed = ip_address(ip)
            if network is not None and parsed not in network:
                continue
        except ValueError:
            continue
        affected_ips.add(ip)
        affected_ids.append(device_id)

    rule_rows = await db.execute(select(FirewallRule.target_ip).where(FirewallRule.target_ip != server_ip))
    for (ip,) in rule_rows.all():
        try:
            parsed = ip_address(ip)
            if network is not None and parsed not in network:
                continue
            affected_ips.add(ip)
        except ValueError:
            continue

    packet_rows = await db.execute(
        select(CapturedPacket.src_ip, CapturedPacket.dst_ip).where(
            (CapturedPacket.src_ip == server_ip) | (CapturedPacket.dst_ip == server_ip)
        )
    )
    for src_ip, dst_ip in packet_rows.all():
        candidate = dst_ip if src_ip == server_ip else src_ip
        try:
            parsed = ip_address(candidate)
            if network is not None and parsed not in network:
                continue
            affected_ips.add(candidate)
        except ValueError:
            continue

    if not affected_ips:
        return {"packets": 0, "threats": 0, "rules": 0, "devices": 0}

    affected_ip_list = list(affected_ips)
    packet_result = await db.execute(
        delete(CapturedPacket).where(
            (
                (CapturedPacket.src_ip == server_ip)
                & CapturedPacket.dst_ip.in_(affected_ip_list)
                & CapturedPacket.dst_port.in_(scanner_ports)
            )
            | (
                CapturedPacket.src_ip.in_(affected_ip_list)
                & (CapturedPacket.dst_ip == server_ip)
                & CapturedPacket.src_port.in_(scanner_ports)
            )
        )
    )
    threat_result = await db.execute(
        delete(ThreatEvent).where(
            ThreatEvent.src_ip.in_(affected_ip_list),
            ThreatEvent.dst_ip == server_ip,
            ThreatEvent.dst_port >= 1024,
        )
    )
    rule_result = await db.execute(
        update(FirewallRule)
        .where(
            FirewallRule.target_ip.in_(affected_ip_list),
            FirewallRule.is_active == True,  # noqa: E712
        )
        .values(is_active=False, removed_at=utc_now_naive())
    )
    device_result = await db.execute(
        update(Device)
        .where(Device.id.in_(affected_ids), Device.risk_score < 0.9)
        .values(risk_score=0.0)
    )
    return {
        "packets": int(packet_result.rowcount or 0),
        "threats": int(threat_result.rowcount or 0),
        "rules": int(rule_result.rowcount or 0),
        "devices": int(device_result.rowcount or 0),
    }


async def get_captured_packet_stats(db: AsyncSession) -> dict:
    """Aggregated stats for dashboard: total, by protocol, by threat type."""
    total = (await db.execute(select(func.count()).select_from(CapturedPacket))).scalar_one()
    threat_count = (await db.execute(
        select(func.count()).select_from(CapturedPacket).where(CapturedPacket.threat_type.isnot(None))
    )).scalar_one()

    # By protocol
    proto_q = (
        select(CapturedPacket.protocol, func.count())
        .group_by(CapturedPacket.protocol)
    )
    by_protocol = {row[0]: row[1] for row in (await db.execute(proto_q)).all()}

    return {
        "total_captured": total,
        "threat_packets": threat_count,
        "normal_packets": total - threat_count,
        "by_protocol": by_protocol,
    }
