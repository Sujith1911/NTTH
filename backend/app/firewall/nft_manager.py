"""
nftables firewall manager - wraps the 'nft' CLI via async subprocess.
All rules are added to dedicated NTTH-owned tables/chains to allow safe rollback.
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

_FILTER_TABLE_FAMILY = "inet"
_FILTER_TABLE_NAME = "ntth_filter"
_FILTER_CHAIN = "ntth_input"
_NAT_TABLE_FAMILY = "ip"
_NAT_TABLE_NAME = "ntth_nat"
_NAT_CHAIN = "ntth_prerouting"


def _table_ref(family: str, table: str) -> tuple[str, str]:
    return family, table


def _chain_ref(family: str, table: str, chain: str) -> tuple[str, str, str]:
    return family, table, chain


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
    async def ensure_infra(self) -> None:
        """Create the dedicated NTTH tables/chains if they do not exist yet."""
        await _run_nft("add", "table", *_table_ref(_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME))
        await _run_nft(
            "add",
            "chain",
            *_chain_ref(_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FILTER_CHAIN),
            "{ type filter hook input priority 0; }",
        )
        await _run_nft("add", "table", *_table_ref(_NAT_TABLE_FAMILY, _NAT_TABLE_NAME))
        await _run_nft(
            "add",
            "chain",
            *_chain_ref(_NAT_TABLE_FAMILY, _NAT_TABLE_NAME, _NAT_CHAIN),
            "{ type nat hook prerouting priority dstnat; }",
        )

    async def ensure_chain(self) -> None:
        """Backward-compatible alias for creating NTTH-owned nft infrastructure."""
        await self.ensure_infra()

    async def add_rate_limit(
        self,
        src_ip: str,
        pps: int = 50,
        *,
        persist: bool = True,
        created_by: str = "system",
        reason: Optional[str] = None,
    ) -> Optional[str]:
        """Rate-limit an IP to `pps` packets/second."""
        await self.ensure_infra()
        rule = f"ip saddr {src_ip} limit rate over {pps}/second drop"
        rc, stdout, stderr = await _run_nft(
            "add",
            "rule",
            *_chain_ref(_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FILTER_CHAIN),
            *rule.split(),
        )
        if rc == 0:
            handle = await self._get_rule_handle(
                _FILTER_TABLE_FAMILY,
                _FILTER_TABLE_NAME,
                _FILTER_CHAIN,
                rule,
            )
            if persist:
                await track_rule(
                    src_ip,
                    "rate_limit",
                    f"filter:{handle}",
                    created_by=created_by,
                    reason=reason,
                )
            log.info("nft_manager.rate_limited", ip=src_ip, handle=handle)
            return f"filter:{handle}"
        log.error("nft_manager.rate_limit_failed", ip=src_ip, error=stderr)
        return None

    async def add_block(
        self,
        src_ip: str,
        *,
        persist: bool = True,
        created_by: str = "system",
        reason: Optional[str] = None,
    ) -> Optional[str]:
        """Drop all traffic from src_ip."""
        await self.ensure_infra()
        rule = f"ip saddr {src_ip} drop"
        rc, _, stderr = await _run_nft(
            "add",
            "rule",
            *_chain_ref(_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FILTER_CHAIN),
            *rule.split(),
        )
        if rc == 0:
            handle = await self._get_rule_handle(
                _FILTER_TABLE_FAMILY,
                _FILTER_TABLE_NAME,
                _FILTER_CHAIN,
                rule,
            )
            if persist:
                await track_rule(
                    src_ip,
                    "block",
                    f"filter:{handle}",
                    created_by=created_by,
                    reason=reason,
                )
            log.warning("nft_manager.blocked", ip=src_ip, handle=handle)
            return f"filter:{handle}"
        log.error("nft_manager.block_failed", ip=src_ip, error=stderr)
        return None

    async def add_redirect(
        self,
        src_ip: str,
        src_port: int,
        dst_port: int,
        *,
        persist: bool = True,
        created_by: str = "system",
        reason: Optional[str] = None,
    ) -> Optional[str]:
        """Redirect src_ip TCP traffic from src_port to dst_port (honeypot)."""
        await self.ensure_infra()
        rule = (
            f"ip saddr {src_ip} tcp dport {src_port} "
            f"redirect to :{dst_port}"
        )
        rc, _, stderr = await _run_nft(
            "add",
            "rule",
            *_chain_ref(_NAT_TABLE_FAMILY, _NAT_TABLE_NAME, _NAT_CHAIN),
            *rule.split(),
        )
        if rc == 0:
            handle = await self._get_rule_handle(
                _NAT_TABLE_FAMILY,
                _NAT_TABLE_NAME,
                _NAT_CHAIN,
                rule,
            )
            if persist:
                await track_rule(
                    src_ip,
                    "redirect",
                    f"nat:{handle}",
                    target_port=dst_port,
                    created_by=created_by,
                    reason=reason,
                )
            log.info("nft_manager.redirected", ip=src_ip, from_port=src_port, to_port=dst_port)
            return f"nat:{handle}"
        log.error("nft_manager.redirect_failed", ip=src_ip, error=stderr)
        return None

    async def delete_rule(self, handle: str) -> bool:
        """Delete a rule by its handle."""
        zone, raw_handle = self._split_handle(handle)
        family, table, chain = (
            (_NAT_TABLE_FAMILY, _NAT_TABLE_NAME, _NAT_CHAIN)
            if zone == "nat"
            else (_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FILTER_CHAIN)
        )
        rc, _, stderr = await _run_nft("delete", "rule", family, table, chain, "handle", raw_handle)
        success = rc == 0
        if success:
            log.info("nft_manager.rule_deleted", handle=handle)
        else:
            log.error("nft_manager.delete_failed", handle=handle, error=stderr)
        return success

    async def flush_chain(self) -> bool:
        """Emergency: remove ALL rules in the ntth chain."""
        await self.ensure_infra()
        filter_rc, _, _ = await _run_nft(
            "flush",
            "chain",
            *_chain_ref(_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FILTER_CHAIN),
        )
        nat_rc, _, _ = await _run_nft(
            "flush",
            "chain",
            *_chain_ref(_NAT_TABLE_FAMILY, _NAT_TABLE_NAME, _NAT_CHAIN),
        )
        success = filter_rc == 0 and nat_rc == 0
        log.warning("nft_manager.chain_flushed", success=success)
        return success

    async def list_rules(self) -> str:
        """Return raw nft rule listing for the ntth chain."""
        await self.ensure_infra()
        _, filter_stdout, _ = await _run_nft(
            "-a",
            "list",
            "chain",
            *_chain_ref(_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FILTER_CHAIN),
        )
        _, nat_stdout, _ = await _run_nft(
            "-a",
            "list",
            "chain",
            *_chain_ref(_NAT_TABLE_FAMILY, _NAT_TABLE_NAME, _NAT_CHAIN),
        )
        return f"{filter_stdout}\n{nat_stdout}".strip()

    async def _get_rule_handle(self, family: str, table: str, chain: str, rule_fragment: str) -> str:
        """Parse the handle of a specific rule from the chain listing."""
        _, stdout, _ = await _run_nft("-a", "list", "chain", family, table, chain)
        normalized = " ".join(rule_fragment.split())
        for line in stdout.splitlines():
            if normalized in " ".join(line.split()):
                match = re.search(r"# handle (\d+)", line)
                if match:
                    return match.group(1)
        return "unknown"

    @staticmethod
    def _split_handle(handle: str) -> tuple[str, str]:
        if ":" in handle:
            return tuple(handle.split(":", 1))  # type: ignore[return-value]
        return "filter", handle
