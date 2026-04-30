"""
Enforcement Agent — translates decisions into nftables rules and honeypot actions.
Subscribes to 'enforcement_action'.
"""
from __future__ import annotations

import asyncio

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
    incident_context = payload.get("incident_context", {})

    if action == "allow":
        return

    await event_bus.publish("report_event", payload)

    if action == "log":
        return

    asyncio.create_task(_apply_enforcement(payload), name=f"enforce_{src_ip}_{action}")


async def _apply_enforcement(payload: dict) -> None:
    action = payload.get("action")
    src_ip = payload.get("src_ip", "")
    dst_ip = payload.get("dst_ip")
    dst_port = payload.get("dst_port")
    protocol = payload.get("protocol", "tcp")
    incident_context = payload.get("incident_context", {})

    if not settings.firewall_enabled:
        log.info("enforcement_agent.firewall_disabled", action=action, ip=src_ip)
        return

    try:
        from app.firewall.nft_manager import NFTManager
        from app.firewall.rule_tracker import is_rule_active

        nft = NFTManager()

        if action == "rate_limit":
            if not await is_rule_active(src_ip, "rate_limit"):
                await nft.add_rate_limit(
                    src_ip,
                    reason=incident_context.get("response_summary") or "Automatic responder throttled a suspicious source.",
                )
                log.info("enforcement_agent.rate_limited", ip=src_ip)

        elif action == "honeypot":
            if not await is_rule_active(
                src_ip,
                "redirect",
                match_dst_ip=dst_ip,
                match_dst_port=dst_port,
            ):
                honeypot_port = incident_context.get("honeypot_port") or settings.cowrie_redirect_port
                handle = await nft.add_redirect(
                    src_ip,
                    src_port=dst_port or 80,
                    dst_port=honeypot_port,
                    dst_ip=dst_ip,
                    reason=incident_context.get("response_summary") or "Automatic responder diverted a hostile source to the honeypot.",
                )
                if handle:
                    try:
                        from app.honeypot.session_logger import register_redirect_context
                        register_redirect_context(
                            attacker_ip=src_ip,
                            observed_attacker_ip=src_ip,
                            victim_ip=dst_ip,
                            victim_port=dst_port,
                            honeypot_type="ssh" if honeypot_port == settings.cowrie_redirect_port else "http",
                            honeypot_port=honeypot_port,
                        )
                    except Exception as exc:
                        log.debug("enforcement_agent.redirect_context_failed", error=str(exc))

                    # Auto-deploy a multi-honeypot on the originally attacked port
                    # so any retry hits a live lure — regardless of which port was targeted
                    if dst_port and dst_port not in (8000, 8001, settings.cowrie_redirect_port):
                        try:
                            from app.honeypot.multi_honeypot import deploy_honeypot, get_protocol_name
                            deployed = await deploy_honeypot(dst_port)
                            if deployed:
                                log.info(
                                    "enforcement_agent.multi_honeypot_deployed",
                                    port=dst_port,
                                    protocol=get_protocol_name(dst_port),
                                    attacker_ip=src_ip,
                                )
                        except Exception as exc:
                            log.debug("enforcement_agent.multi_honeypot_deploy_failed", error=str(exc))

                if handle and honeypot_port == settings.cowrie_redirect_port:
                    try:
                        from app.honeypot.cowrie_controller import ensure_cowrie_running
                        await asyncio.wait_for(ensure_cowrie_running(), timeout=2)
                    except asyncio.TimeoutError:
                        log.warning("enforcement_agent.cowrie_start_timeout", ip=src_ip)
                    except Exception as exc:
                        log.warning("enforcement_agent.cowrie_start_failed", error=str(exc))
                if handle:
                    log.info("enforcement_agent.redirected_to_honeypot", ip=src_ip, victim_ip=dst_ip, victim_port=dst_port)

        elif action == "block":
            if not await is_rule_active(src_ip, "block"):
                await nft.add_block(
                    src_ip,
                    reason=incident_context.get("response_summary") or "Automatic responder blocked a high-risk source.",
                )
                log.warning("enforcement_agent.blocked", ip=src_ip, risk_score=payload.get("risk_score"))

    except Exception as exc:
        log.error("enforcement_agent.error", action=action, ip=src_ip, error=str(exc))


event_bus.subscribe("enforcement_action", _handle_enforcement_action)
