"""
Enforcement Agent — translates decisions into nftables rules and honeypot actions.
Subscribes to 'enforcement_action'.
"""
from __future__ import annotations

from app.config import get_settings
from app.core import event_bus
from app.core.logger import get_logger

log = get_logger("enforcement_agent")
settings = get_settings()


async def _handle_enforcement_action(payload: dict) -> None:
    action = payload.get("action")
    src_ip = payload.get("src_ip", "")
    dst_port = payload.get("dst_port")
    protocol = payload.get("protocol", "tcp")

    if action == "allow":
        return

    # Log action: skip firewall enforcement but still report
    if action == "log":
        await event_bus.publish("report_event", payload)
        return

    if not settings.firewall_enabled:
        log.info("enforcement_agent.firewall_disabled", action=action, ip=src_ip)
        await event_bus.publish("report_event", payload)
        return

    try:
        from app.firewall.nft_manager import NFTManager
        from app.firewall.rule_tracker import is_rule_active

        nft = NFTManager()

        if action == "rate_limit":
            if not await is_rule_active(src_ip, "rate_limit"):
                await nft.add_rate_limit(src_ip)
                log.info("enforcement_agent.rate_limited", ip=src_ip)

        elif action == "honeypot":
            if not await is_rule_active(src_ip, "redirect"):
                await nft.add_redirect(
                    src_ip,
                    src_port=dst_port or 22,
                    dst_port=settings.cowrie_redirect_port,
                )
                # Start Cowrie if needed
                try:
                    from app.honeypot.cowrie_controller import ensure_cowrie_running
                    await ensure_cowrie_running()
                except Exception as exc:
                    log.warning("enforcement_agent.cowrie_start_failed", error=str(exc))
                log.info("enforcement_agent.redirected_to_honeypot", ip=src_ip)

        elif action == "block":
            if not await is_rule_active(src_ip, "block"):
                await nft.add_block(src_ip)
                log.warning("enforcement_agent.blocked", ip=src_ip, risk_score=payload.get("risk_score"))

    except Exception as exc:
        log.error("enforcement_agent.error", action=action, ip=src_ip, error=str(exc))

    # Forward to reporting agent regardless of firewall state
    await event_bus.publish("report_event", payload)


event_bus.subscribe("enforcement_action", _handle_enforcement_action)
