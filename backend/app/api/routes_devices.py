"""
Device routes: list devices, get device details, trust toggle, and stats history.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

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

router = APIRouter()
settings = get_settings()


@router.get("", response_model=PaginatedResponse)
async def list_devices(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    total, devices = await crud.list_devices(db, page, page_size)
    return PaginatedResponse(
        total=total, page=page, page_size=page_size,
        items=[DeviceRead.model_validate(d) for d in devices],
    )


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
    device.risk_score = 0.0
    deactivated_rules = await crud.deactivate_firewall_rules_for_ip(db, device.ip_address)
    scanner_cleanup = await crud.purge_scanner_false_positive_for_ip(
        db,
        device_ip=device.ip_address,
        server_ip=settings.server_display_ip,
    )
    normal_cleanup = await crud.purge_low_risk_normal_events_for_ip(db, device.ip_address)
    broadcast_cleanup = await crud.purge_lan_broadcast_events_for_ip(db, device.ip_address)

    # Remove live nftables rules for this IP when nftables is available.
    removed_rules = 0
    try:
        from app.firewall.nft_manager import NFTManager
        nft = NFTManager()
        removed_rules = await nft.remove_rules_for_ip(device.ip_address, update_db=False)
    except Exception:
        pass  # Firewall may not be active

    await db.commit()
    await db.refresh(device)

    await broadcast({
        "type": "device_updated",
        "ip": device.ip_address,
        "risk_score": device.risk_score,
        "unblocked": True,
        "removed_rules": removed_rules,
        "deactivated_rules": deactivated_rules,
        "scanner_cleanup": scanner_cleanup,
        "normal_cleanup": normal_cleanup,
        "broadcast_cleanup": broadcast_cleanup,
    })

    return DeviceRead.model_validate(device)
