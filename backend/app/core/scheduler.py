"""
APScheduler-based background scheduler.
Jobs: firewall rule cleanup, ML model retrain, health check heartbeat.
"""
from __future__ import annotations

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.logger import get_logger

log = get_logger("scheduler")

_scheduler: AsyncIOScheduler | None = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(timezone="UTC")
    return _scheduler


async def start_scheduler() -> None:
    from app.firewall.rule_cleanup import cleanup_expired_rules
    from app.ids.anomaly_model import retrain_model_if_needed

    scheduler = get_scheduler()

    scheduler.add_job(
        cleanup_expired_rules,
        trigger=IntervalTrigger(minutes=5),
        id="firewall_cleanup",
        replace_existing=True,
        name="Firewall Rule Cleanup",
    )

    scheduler.add_job(
        retrain_model_if_needed,
        trigger=IntervalTrigger(hours=6),
        id="ml_retrain",
        replace_existing=True,
        name="ML Model Retrain",
    )

    from app.monitor.device_sync import sync_device_registry
    scheduler.add_job(
        sync_device_registry,
        trigger=IntervalTrigger(seconds=60),
        id="device_sync",
        replace_existing=True,
        name="Device Registry DB Sync",
    )

    scheduler.start()
    log.info("scheduler.started", jobs=[j.id for j in scheduler.get_jobs()])


async def stop_scheduler() -> None:
    scheduler = get_scheduler()
    if scheduler.running:
        scheduler.shutdown(wait=False)
        log.info("scheduler.stopped")
