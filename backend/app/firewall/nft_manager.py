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
_FORWARD_CHAIN = "ntth_forward"
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
        # Forward chain at priority 0 (not -10) so Scapy on the bridge can
        # still see all packets before nftables acts on them.
        await _run_nft(
            "add",
            "chain",
            *_chain_ref(_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FORWARD_CHAIN),
            "{ type filter hook forward priority 0; }",
        )
        # Accept established/related connections so blocking a NEW attacker
        # doesn't tear down existing sessions (dashboard, SSH, etc.)
        await _run_nft(
            "add", "rule",
            *_chain_ref(_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FORWARD_CHAIN),
            "ct", "state", "established,related", "accept",
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
        ttl_seconds: Optional[int] = 0,
    ) -> Optional[str]:
        """Drop forwarded internet traffic from src_ip while keeping gateway/server access.

        Only blocks FORWARDED traffic (VM-to-internet, VM-to-VM), never INPUT
        (device-to-gateway). Real WiFi devices' gateway/DNS/dashboard access is preserved.
        """
        protected_ips = {settings.gateway_ip, settings.server_display_ip, "127.0.0.1"}
        if src_ip in protected_ips:
            log.warning("nft_manager.block_refused_infrastructure_ip", ip=src_ip)
            return None
        await self.ensure_infra()
        # Build exception: gateway + server (so dashboard remains reachable)
        # When both are the same IP (e.g., 192.168.4.1), use single IP syntax
        exception_ips = {ip for ip in (settings.gateway_ip, settings.server_display_ip) if ip}
        if len(exception_ips) > 1:
            # Use nft anonymous set: ip daddr != { ip1, ip2 } drop
            ip_list = ", ".join(sorted(exception_ips))
            rule_parts = [
                "ip", "saddr", src_ip,
                "ip", "daddr", "!=", "{", ip_list, "}",
                "drop",
            ]
        else:
            safe_ip = next(iter(exception_ips)) if exception_ips else settings.gateway_ip
            rule_parts = f"ip saddr {src_ip} ip daddr != {safe_ip} drop".split()
        rc, _, stderr = await _run_nft(
            "add",
            "rule",
            *_chain_ref(_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FORWARD_CHAIN),
            *rule_parts,
        )
        if rc == 0:
            rule_str = " ".join(rule_parts)
            handle = await self._get_rule_handle(
                _FILTER_TABLE_FAMILY,
                _FILTER_TABLE_NAME,
                _FORWARD_CHAIN,
                rule_str,
            )
            if persist:
                await track_rule(
                    src_ip,
                    "block",
                    f"forward:{handle}",
                    created_by=created_by,
                    reason=reason,
                    ttl_seconds=ttl_seconds,
                )
            log.warning("nft_manager.blocked", ip=src_ip, handle=handle)
            return f"forward:{handle}"
        log.error("nft_manager.block_failed", ip=src_ip, error=stderr)
        return None

    async def add_redirect(
        self,
        src_ip: str,
        src_port: int,
        dst_port: int,
        *,
        dst_ip: Optional[str] = None,
        persist: bool = True,
        created_by: str = "system",
        reason: Optional[str] = None,
    ) -> Optional[str]:
        """Redirect src_ip TCP traffic from src_port to the honeypot via iptables DNAT.

        Uses iptables instead of nftables because iptables has better support
        for br_netfilter — critical for redirecting bridged VM-to-VM traffic.
        After adding the rule, conntrack is flushed so existing connections
        are re-evaluated through the new DNAT rule.
        """
        gateway_ip = settings.gateway_ip

        # Build iptables DNAT rule — scoped to bridge interface only
        # -i br-ntth ensures only bridge traffic is affected, never upstream WiFi
        bridge = settings.network_interface  # br-ntth
        ipt_cmd = [
            "iptables", "-t", "nat", "-I", "PREROUTING",
            "-i", bridge,
            "-s", src_ip,
            "-p", "tcp", "--dport", str(src_port),
        ]
        if dst_ip:
            ipt_cmd += ["-d", dst_ip]
        ipt_cmd += ["-j", "DNAT", "--to-destination", f"{gateway_ip}:{dst_port}"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *ipt_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            rc = proc.returncode
        except Exception as exc:
            log.error("nft_manager.iptables_redirect_failed", error=str(exc))
            return None

        if rc == 0:
            handle_id = f"ipt-{src_ip}-{src_port}-{dst_port}"
            if persist:
                await track_rule(
                    src_ip,
                    "redirect",
                    f"ipt:{handle_id}",
                    target_port=dst_port,
                    match_dst_ip=dst_ip,
                    match_dst_port=src_port,
                    created_by=created_by,
                    reason=reason,
                )
            log.info("nft_manager.redirected", ip=src_ip, from_port=src_port,
                     to_port=dst_port, gateway=gateway_ip, method="iptables")

            # Flush ONLY the attacker's conntrack entries — never full flush
            # Full flush (conntrack -F) would kill ALL device connections
            # causing WiFi disconnections for phones/laptops
            try:
                flush_proc = await asyncio.create_subprocess_exec(
                    "conntrack", "-D", "-s", src_ip,
                    "-p", "tcp", "--dport", str(src_port),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await flush_proc.communicate()
                log.debug("nft_manager.conntrack_flushed", ip=src_ip, port=src_port)
            except FileNotFoundError:
                log.warning("nft_manager.conntrack_not_installed",
                            hint="Install conntrack: sudo apt install conntrack")
            except Exception:
                pass

            return f"ipt:{handle_id}"

        log.error("nft_manager.redirect_failed", ip=src_ip,
                  error=stderr.decode() if isinstance(stderr, bytes) else stderr)
        return None

    async def delete_rule(self, handle: str) -> bool:
        """Delete a rule by its handle."""
        zone, raw_handle = self._split_handle(handle)

        # iptables-based redirect rules
        if zone == "ipt":
            # Handle format: ipt-<src_ip>-<src_port>-<dst_port>
            parts = raw_handle.split("-")
            if len(parts) >= 3:
                src_ip = "-".join(parts[:-2])  # IP may not contain hyphens, but be safe
                src_port = parts[-2]
                dst_port = parts[-1]
                gateway_ip = settings.gateway_ip
                bridge = settings.network_interface
                ipt_cmd = [
                    "iptables", "-t", "nat", "-D", "PREROUTING",
                    "-i", bridge,
                    "-s", src_ip,
                    "-p", "tcp", "--dport", src_port,
                    "-j", "DNAT", "--to-destination", f"{gateway_ip}:{dst_port}",
                ]
                try:
                    proc = await asyncio.create_subprocess_exec(
                        *ipt_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await proc.communicate()
                    success = proc.returncode == 0
                except Exception:
                    success = False
            else:
                success = False
            if success:
                log.info("nft_manager.rule_deleted", handle=handle, method="iptables")
            else:
                log.error("nft_manager.delete_failed", handle=handle)
            return success

        # nftables-based rules (block, filter)
        if zone == "nat":
            family, table, chain = (_NAT_TABLE_FAMILY, _NAT_TABLE_NAME, _NAT_CHAIN)
        elif zone == "forward":
            family, table, chain = (_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FORWARD_CHAIN)
        else:
            family, table, chain = (_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FILTER_CHAIN)
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
        forward_rc, _, _ = await _run_nft(
            "flush",
            "chain",
            *_chain_ref(_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FORWARD_CHAIN),
        )
        nat_rc, _, _ = await _run_nft(
            "flush",
            "chain",
            *_chain_ref(_NAT_TABLE_FAMILY, _NAT_TABLE_NAME, _NAT_CHAIN),
        )
        success = filter_rc == 0 and forward_rc == 0 and nat_rc == 0
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
        _, forward_stdout, _ = await _run_nft(
            "-a",
            "list",
            "chain",
            *_chain_ref(_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FORWARD_CHAIN),
        )
        return f"{filter_stdout}\n{forward_stdout}\n{nat_stdout}".strip()

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

    async def remove_rules_for_ip(self, ip: str, *, update_db: bool = True) -> int:
        """Remove ALL rules (block, rate-limit, redirect) matching the given IP."""
        removed = 0
        for family, table, chain in [
            (_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FILTER_CHAIN),
            (_FILTER_TABLE_FAMILY, _FILTER_TABLE_NAME, _FORWARD_CHAIN),
            (_NAT_TABLE_FAMILY, _NAT_TABLE_NAME, _NAT_CHAIN),
        ]:
            _, stdout, _ = await _run_nft("-a", "list", "chain", family, table, chain)
            for line in stdout.splitlines():
                if ip in line:
                    match = re.search(r"# handle (\d+)", line)
                    if match:
                        handle = match.group(1)
                        rc, _, _ = await _run_nft("delete", "rule", family, table, chain, "handle", handle)
                        if rc == 0:
                            removed += 1
                            log.info("nft_manager.rule_removed_for_ip", ip=ip, handle=handle)
        if update_db:
            try:
                from app.database.session import AsyncSessionLocal
                from app.database import crud
                async with AsyncSessionLocal() as db:
                    await crud.deactivate_firewall_rules_for_ip(db, ip)
                    await db.commit()
            except Exception as exc:
                log.debug("nft_manager.db_cleanup_failed", ip=ip, error=str(exc))
        return removed

    @staticmethod
    def _split_handle(handle: str) -> tuple[str, str]:
        if ":" in handle:
            zone, raw_handle = handle.split(":", 1)
            if zone == "forward":
                return "forward", raw_handle
            return zone, raw_handle
        return "filter", handle
