"""
Rule tracker — maintains DB record of active firewall rules.
Prevents duplicate rules and tracks handles for later removal.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from app.config import get_settings
from app.database.crud import create_firewall_rule, rule_exists_for_ip
from app.database.session import AsyncSessionLocal

settings = get_settings()


async def track_rule(
    target_ip: str,
    rule_type: str,
    nft_handle: Optional[str] = None,
    target_port: Optional[int] = None,
    ttl_seconds: Optional[int] = None,
    created_by: str = "system",
    reason: Optional[str] = None,
) -> None:
    """Persist a new firewall rule in the DB."""
    ttl = ttl_seconds or settings.firewall_rule_ttl_seconds
    expires_at = datetime.utcnow() + timedelta(seconds=ttl)

    async with AsyncSessionLocal() as db:
        await create_firewall_rule(
            db,
            rule_type=rule_type,
            target_ip=target_ip,
            target_port=target_port,
            nft_handle=nft_handle,
            is_active=True,
            created_by=created_by,
            expires_at=expires_at,
            reason=reason,
        )
        await db.commit()


async def is_rule_active(target_ip: str, rule_type: str) -> bool:
    """Return True if an active rule of this type already exists for the IP."""
    async with AsyncSessionLocal() as db:
        return await rule_exists_for_ip(db, target_ip, rule_type)
