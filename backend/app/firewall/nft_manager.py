"""
nftables firewall manager — wraps the 'nft' CLI via async subprocess.
All rules are added to a dedicated chain to allow safe rollback.
"""
from __future__ import annotations

import asyncio
import re
from typing import Optional

from app.config import get_settings
from app.core.logger import get_logger
from app.firewall.rule_tracker import track_rule

log = get_logger("nft_manager")
settings = get_settings()

_TABLE = "inet filter"
_CHAIN = "ntth_input"


async def _run_nft(*args: str) -> tuple[int, str, str]:
    """Execute an nft command and return (returncode, stdout, stderr)."""
    cmd = ["nft"] + list(args)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode(), stderr.decode()
    except FileNotFoundError:
        log.warning("nft_manager.nft_not_found", hint="nftables not installed or not on PATH")
        return 1, "", "nft not found"
    except Exception as exc:
        log.error("nft_manager.subprocess_error", error=str(exc))
        return 1, "", str(exc)


class NFTManager:
    async def ensure_chain(self) -> None:
        """Create the ntth_input chain if it doesn't exist."""
        await _run_nft("add", "chain", _TABLE, _CHAIN, "{ type filter hook input priority 0; }")

    async def add_rate_limit(self, src_ip: str, pps: int = 50) -> Optional[str]:
        """Rate-limit an IP to `pps` packets/second."""
        rule = f"ip saddr {src_ip} limit rate over {pps}/second drop"
        rc, stdout, stderr = await _run_nft("add", "rule", _TABLE, _CHAIN, *rule.split())
        if rc == 0:
            handle = await self._get_last_handle()
            await track_rule(src_ip, "rate_limit", handle)
            log.info("nft_manager.rate_limited", ip=src_ip, handle=handle)
            return handle
        log.error("nft_manager.rate_limit_failed", ip=src_ip, error=stderr)
        return None

    async def add_block(self, src_ip: str) -> Optional[str]:
        """Drop all traffic from src_ip."""
        rule = f"ip saddr {src_ip} drop"
        rc, _, stderr = await _run_nft("add", "rule", _TABLE, _CHAIN, *rule.split())
        if rc == 0:
            handle = await self._get_last_handle()
            await track_rule(src_ip, "block", handle)
            log.warning("nft_manager.blocked", ip=src_ip, handle=handle)
            return handle
        log.error("nft_manager.block_failed", ip=src_ip, error=stderr)
        return None

    async def add_redirect(self, src_ip: str, src_port: int, dst_port: int) -> Optional[str]:
        """Redirect src_ip TCP traffic from src_port to dst_port (honeypot)."""
        rule = (
            f"ip saddr {src_ip} tcp dport {src_port} "
            f"redirect to :{dst_port}"
        )
        rc, _, stderr = await _run_nft("add", "rule", "ip nat", "PREROUTING", *rule.split())
        if rc == 0:
            handle = await self._get_last_handle()
            await track_rule(src_ip, "redirect", handle)
            log.info("nft_manager.redirected", ip=src_ip, from_port=src_port, to_port=dst_port)
            return handle
        log.error("nft_manager.redirect_failed", ip=src_ip, error=stderr)
        return None

    async def delete_rule(self, handle: str) -> bool:
        """Delete a rule by its handle."""
        rc, _, stderr = await _run_nft("delete", "rule", _TABLE, _CHAIN, "handle", handle)
        success = rc == 0
        if success:
            log.info("nft_manager.rule_deleted", handle=handle)
        else:
            log.error("nft_manager.delete_failed", handle=handle, error=stderr)
        return success

    async def flush_chain(self) -> bool:
        """Emergency: remove ALL rules in the ntth chain."""
        rc, _, _ = await _run_nft("flush", "chain", _TABLE, _CHAIN)
        log.warning("nft_manager.chain_flushed", success=(rc == 0))
        return rc == 0

    async def list_rules(self) -> str:
        """Return raw nft rule listing for the ntth chain."""
        _, stdout, _ = await _run_nft("list", "chain", _TABLE, _CHAIN)
        return stdout

    async def _get_last_handle(self) -> str:
        """Parse the handle of the most recently added rule."""
        _, stdout, _ = await _run_nft("list", "chain", _TABLE, _CHAIN)
        handles = re.findall(r"# handle (\d+)", stdout)
        return handles[-1] if handles else "unknown"
