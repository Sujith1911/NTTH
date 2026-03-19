"""
Periodic device registry DB sync.
Flushes in-memory device registry to the database every 60 seconds.
This is added to the APScheduler via start_scheduler().
"""
from __future__ import annotations

from app.core.logger import get_logger
from app.database import crud
from app.database.models import DeviceStat
from app.database.session import AsyncSessionLocal
from app.monitor import device_registry

log = get_logger("device_sync")


async def sync_device_registry() -> None:
    """
    For every IP tracked in memory:
      - Upsert the Device row
      - Append a DeviceStat snapshot
    """
    ips = device_registry.get_all_ips()
    if not ips:
        return

    async with AsyncSessionLocal() as db:
        for ip in ips:
            state = device_registry.get_state(ip)
            if not state:
                continue
            try:
                device, _ = await crud.get_or_create_device(db, ip)
                stat = DeviceStat(
                    device_id=device.id,
                    packet_count=state.get("packet_count", 0),
                    byte_count=state.get("byte_count", 0),
                    unique_ports=state.get("unique_ports", 0),
                    syn_count=state.get("syn_count", 0),
                )
                await crud.add_device_stat(db, stat)
            except Exception as exc:
                log.error("device_sync.error", ip=ip, error=str(exc))
        await db.commit()

    log.debug("device_sync.done", ips=len(ips))
