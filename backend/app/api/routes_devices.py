"""
Device routes: list devices, get device details, trust toggle, and stats history.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import crud
from app.database.schemas import (
    DeviceRead,
    DeviceStatRead,
    DeviceTrustUpdate,
    PaginatedResponse,
)
from app.dependencies import get_current_user, get_db, require_admin

router = APIRouter()


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
