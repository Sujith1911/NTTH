"""Research/evaluation endpoints for conference-paper measurements."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Body, Depends, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database.models import CapturedPacket, FirewallRule, HoneypotSession, ThreatEvent
from app.dependencies import get_db, require_admin
from app.research import metrics

router = APIRouter()
settings = get_settings()


def _sqlite_db_path() -> Path | None:
    prefix = "sqlite+aiosqlite:///"
    if not settings.database_url.startswith(prefix):
        return None
    return Path(settings.database_url.removeprefix(prefix))


def _db_size_bytes() -> int | None:
    path = _sqlite_db_path()
    if not path:
        return None
    try:
        return path.stat().st_size
    except OSError:
        return None


@router.post("/experiments/start")
async def start_experiment(
    payload: dict = Body(default={}),
    _admin=Depends(require_admin),
):
    """Start labeling subsequent telemetry with an experiment id."""
    return metrics.start_experiment(
        name=str(payload.get("name") or "unnamed_experiment"),
        scenario=payload.get("scenario"),
        notes=payload.get("notes"),
    )


@router.post("/experiments/stop")
async def stop_experiment(_admin=Depends(require_admin)):
    """Stop the active experiment label."""
    return {"stopped": metrics.stop_experiment()}


@router.get("/metrics")
async def research_metrics(
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_admin),
):
    """Return live paper-evaluation counters and system snapshot."""
    counts = {
        "captured_packets": (await db.execute(select(func.count()).select_from(CapturedPacket))).scalar_one(),
        "threat_events": (await db.execute(select(func.count()).select_from(ThreatEvent))).scalar_one(),
        "honeypot_sessions": (await db.execute(select(func.count()).select_from(HoneypotSession))).scalar_one(),
        "active_firewall_rules": (
            await db.execute(
                select(func.count()).select_from(FirewallRule).where(FirewallRule.is_active == True)  # noqa: E712
            )
        ).scalar_one(),
    }
    return {
        "summary": metrics.summary(),
        "system": metrics.system_snapshot(db_size_bytes=_db_size_bytes()),
        "database_counts": counts,
    }


@router.get("/metrics/export.csv")
async def export_metrics_csv(
    limit: int = Query(10000, ge=1, le=100000),
    _admin=Depends(require_admin),
):
    """Export research metrics as CSV for paper tables/graphs."""
    return Response(
        metrics.export_csv(limit=limit),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=ntth_research_metrics.csv"},
    )


@router.get("/metrics/export.jsonl")
async def export_metrics_jsonl(
    limit: int = Query(10000, ge=1, le=100000),
    _admin=Depends(require_admin),
):
    """Export raw research events as JSONL for reproducible analysis."""
    return Response(
        metrics.export_jsonl(limit=limit),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": "attachment; filename=ntth_research_metrics.jsonl"},
    )
