"""
Device routes: list devices, get device details, trust toggle, and stats history.
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time_utils import utc_now_naive
from app.database import crud
from app.config import get_settings
from app.websocket.live_updates import broadcast
from app.database.schemas import (
    DeviceRead,
    DeviceStatRead,
    DeviceTrustUpdate,
    PaginatedResponse,
)
from app.dependencies import get_current_user, get_db, require_admin

import time as _time

router = APIRouter()
settings = get_settings()

# Short-lived cache for device list (avoids DB hit on rapid dashboard polls)
_devices_cache: dict = {}  # key → (result, timestamp)
_DEVICES_CACHE_TTL = 2.0


@router.get("", response_model=PaginatedResponse)
async def list_devices(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    active_only: bool = Query(True),
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    cache_key = (page, page_size, active_only)
    now = _time.monotonic()
    cached = _devices_cache.get(cache_key)
    if cached and (now - cached[1]) < _DEVICES_CACHE_TTL:
        return cached[0]

    presence_seconds = max(120, settings.device_scan_interval_seconds * 2)
    seen_after = (
        utc_now_naive() - timedelta(seconds=presence_seconds)
        if active_only
        else None
    )
    total, devices = await crud.list_devices(
        db,
        page,
        page_size,
        seen_after=seen_after,
        exclude_ips={
            ip
            for ip in (settings.gateway_ip, settings.server_display_ip)
            if ip
        },
    )
    result = PaginatedResponse(
        total=total, page=page, page_size=page_size,
        items=[DeviceRead.model_validate(d) for d in devices],
    )
    _devices_cache[cache_key] = (result, now)
    return result


@router.post("/by-ip/{ip_address}/clear-risk")
async def clear_device_risk_by_ip(
    ip_address: str,
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
):
    """Admin-only: reset risk/containment for an IP, even if the device row is stale/missing."""
    try:
        from ipaddress import ip_address as parse_ip
        parsed = str(parse_ip(ip_address))
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid IP address")

    if parsed in {settings.gateway_ip, settings.server_display_ip, "127.0.0.1"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Refusing to modify gateway/server IP")

    device = await crud.get_device_by_ip(db, parsed)
    if device:
        device.risk_score = 0.0

    # Only deactivate firewall rules — do NOT delete threat events or packets
    deactivated_rules = await crud.deactivate_firewall_rules_for_ip(db, parsed)

    removed_rules = 0
    try:
        from app.firewall.nft_manager import NFTManager
        removed_rules = await NFTManager().remove_rules_for_ip(parsed, update_db=False)
    except Exception:
        pass

    try:
        from app.ids.risk_clearance import register_clear
        register_clear(parsed)
    except Exception:
        pass

    # Reset escalation counters so the IP starts fresh
    try:
        from app.ids.risk_calculator import reset_scan_count
        reset_scan_count(parsed)
    except Exception:
        pass
    try:
        from app.honeypot.session_logger import _attacker_command_counts
        _attacker_command_counts.pop(parsed, None)
    except Exception:
        pass

    await db.commit()
    if device:
        await db.refresh(device)

    await broadcast({
        "type": "device_updated",
        "ip": parsed,
        "risk_score": 0.0,
        "unblocked": True,
        "removed_rules": removed_rules,
        "deactivated_rules": deactivated_rules,
    })

    return {
        "ip": parsed,
        "device_id": device.id if device else None,
        "risk_score": 0.0,
        "unblocked": True,
        "removed_rules": removed_rules,
        "deactivated_rules": deactivated_rules,
    }


@router.get("/{device_id}", response_model=DeviceRead)
async def get_device(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    device = await crud.get_device(db, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return DeviceRead.model_validate(device)


@router.put("/{device_id}/trust", response_model=DeviceRead)
async def update_device_trust(
    device_id: str,
    payload: DeviceTrustUpdate,
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
):
    """Admin-only: mark a device as trusted or untrusted."""
    device = await crud.update_device_trust(db, device_id, payload.is_trusted)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return DeviceRead.model_validate(device)


@router.get("/{device_id}/stats", response_model=PaginatedResponse)
async def list_device_stats(
    device_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    """Return paginated traffic stat snapshots for a specific device."""
    # Verify device exists
    device = await crud.get_device(db, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    total, stats = await crud.list_device_stats(db, device_id, page, page_size)
    return PaginatedResponse(
        total=total, page=page, page_size=page_size,
        items=[DeviceStatRead.model_validate(s) for s in stats],
    )


@router.post("/{device_id}/clear-risk", response_model=DeviceRead)
async def clear_device_risk(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
):
    """Admin-only: reset a device's risk score to 0 and remove any firewall rules for it."""
    device = await crud.get_device(db, device_id)
    if not device:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    # Reset risk score and mark any DB-tracked containment rules inactive.
    # Do NOT delete threat events or packets — preserve all historical data.
    device.risk_score = 0.0
    deactivated_rules = await crud.deactivate_firewall_rules_for_ip(db, device.ip_address)

    # Remove live nftables rules for this IP when nftables is available.
    removed_rules = 0
    try:
        from app.firewall.nft_manager import NFTManager
        nft = NFTManager()
        removed_rules = await nft.remove_rules_for_ip(device.ip_address, update_db=False)
    except Exception:
        pass  # Firewall may not be active

    try:
        from app.ids.risk_clearance import register_clear
        register_clear(device.ip_address)
    except Exception:
        pass

    # Reset escalation counters
    try:
        from app.ids.risk_calculator import reset_scan_count
        reset_scan_count(device.ip_address)
    except Exception:
        pass
    try:
        from app.honeypot.session_logger import _attacker_command_counts
        _attacker_command_counts.pop(device.ip_address, None)
    except Exception:
        pass

    await db.commit()
    await db.refresh(device)

    await broadcast({
        "type": "device_updated",
        "ip": device.ip_address,
        "risk_score": device.risk_score,
        "unblocked": True,
        "removed_rules": removed_rules,
        "deactivated_rules": deactivated_rules,
    })

    return DeviceRead.model_validate(device)
