"""
Threat routes: list threat events, acknowledge them, and view type stats.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import crud
from app.database.models import User
from app.database.schemas import (
    PaginatedResponse,
    ThreatAcknowledge,
    ThreatEventRead,
    ThreatStats,
)
from app.dependencies import get_current_user, get_db

router = APIRouter()


@router.get("", response_model=PaginatedResponse)
async def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    unacknowledged_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    total, events = await crud.list_threats(db, page, page_size, unacknowledged_only)
    return PaginatedResponse(
        total=total, page=page, page_size=page_size,
        items=[ThreatEventRead.model_validate(e) for e in events],
    )


@router.get("/stats", response_model=ThreatStats)
async def get_threat_stats(
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    """Return aggregated threat counts grouped by type and action taken."""
    raw = await crud.get_threat_stats(db)
    return ThreatStats(
        total=raw["total"],
        by_type=raw["by_type"],
        by_action=raw["by_action"],
    )


@router.get("/{threat_id}", response_model=ThreatEventRead)
async def get_threat(
    threat_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    from sqlalchemy import select
    from app.database.models import ThreatEvent
    result = await db.execute(select(ThreatEvent).where(ThreatEvent.id == threat_id))
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat not found")
    return ThreatEventRead.model_validate(event)


@router.post("/{threat_id}/acknowledge", response_model=ThreatEventRead)
async def acknowledge_threat(
    threat_id: str,
    payload: ThreatAcknowledge,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    event = await crud.acknowledge_threat(db, threat_id, current_user.username, payload.notes)
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat not found")
    return ThreatEventRead.model_validate(event)
