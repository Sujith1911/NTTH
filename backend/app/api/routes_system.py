"""
System routes: health check, dashboard stats, logs, emergency flush.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import crud
from app.database.schemas import DashboardStats, HealthResponse, PaginatedResponse, SystemLogRead
from app.dependencies import get_current_user, get_db, require_admin

router = APIRouter()
settings = get_settings()


@router.get("/health", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db)):
    db_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass

    # Guard sniffer_running — packet_sniffer is not available on Windows
    sniffer_running = False
    try:
        from app.monitor import packet_sniffer
        sniffer_running = packet_sniffer._running
    except Exception:
        pass

    from app.core.scheduler import get_scheduler
    scheduler = get_scheduler()

    return HealthResponse(
        status="ok" if db_ok else "degraded",
        version=settings.app_version,
        environment=settings.environment,
        db_ok=db_ok,
        sniffer_running=sniffer_running,
        scheduler_running=scheduler.running if scheduler else False,
    )


@router.get("/stats", response_model=DashboardStats)
async def dashboard_stats(
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    """Return aggregate counts for the dashboard (devices, threats, rules, sessions)."""
    raw = await crud.get_dashboard_stats(db)
    return DashboardStats(**raw)


@router.get("/logs", response_model=PaginatedResponse)
async def list_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
):
    total, logs = await crud.list_system_logs(db, page, page_size)
    return PaginatedResponse(
        total=total, page=page, page_size=page_size,
        items=[SystemLogRead.model_validate(l) for l in logs],
    )


@router.post("/emergency-flush")
async def emergency_flush(_admin=Depends(require_admin)):
    """Nuclear option: flush all NTTH nftables rules immediately."""
    from app.firewall.nft_manager import NFTManager
    success = await NFTManager().flush_chain()
    return {"flushed": success, "warning": "All dynamic firewall rules removed"}
