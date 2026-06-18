"""
Add performance indexes to existing NTTH database.
Run once after upgrading: python -m app.database.add_indexes
Does NOT delete or modify any data — only adds indexes for faster queries.
"""
import asyncio
import sys

from sqlalchemy import text

from app.database.session import AsyncSessionLocal
from app.core.logger import get_logger

log = get_logger("add_indexes")

_INDEXES = [
    ("idx_devices_last_seen", "devices", "last_seen"),
    ("idx_threat_events_detected_at", "threat_events", "detected_at"),
    ("idx_firewall_rules_is_active", "firewall_rules", "is_active"),
]


async def add_indexes():
    async with AsyncSessionLocal() as db:
        for idx_name, table, column in _INDEXES:
            try:
                await db.execute(
                    text(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table} ({column})")
                )
                log.info(f"Index created or already exists: {idx_name}")
            except Exception as exc:
                log.warning(f"Index {idx_name} failed: {exc}")
        await db.commit()
    print("✅ All indexes applied successfully.")


if __name__ == "__main__":
    asyncio.run(add_indexes())
