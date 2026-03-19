"""
Scheduler job: expire firewall rules that have passed their TTL.
Called every 5 minutes by APScheduler.
"""
from __future__ import annotations

from app.core.logger import get_logger
from app.database.crud import deactivate_firewall_rule, get_expired_firewall_rules
from app.database.session import AsyncSessionLocal
from app.firewall.nft_manager import NFTManager

log = get_logger("rule_cleanup")


async def cleanup_expired_rules() -> None:
    """Find all expired active rules, remove them from nftables, mark inactive in DB."""
    async with AsyncSessionLocal() as db:
        expired = await get_expired_firewall_rules(db)
        if not expired:
            return

        nft = NFTManager()
        for rule in expired:
            try:
                if rule.nft_handle and rule.nft_handle != "unknown":
                    await nft.delete_rule(rule.nft_handle)
                await deactivate_firewall_rule(db, rule.id)
                log.info(
                    "rule_cleanup.expired",
                    rule_id=rule.id,
                    ip=rule.target_ip,
                    rule_type=rule.rule_type,
                    handle=rule.nft_handle,
                )
            except Exception as exc:
                log.error("rule_cleanup.error", rule_id=rule.id, error=str(exc))

        await db.commit()
        log.info("rule_cleanup.complete", removed=len(expired))
