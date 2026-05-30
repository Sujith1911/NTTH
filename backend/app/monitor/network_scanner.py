"""
Windows-compatible network scanner with port scanning.
Uses:
  1. ARP via scapy (if Npcap installed + admin privileges)
  2. ICMP ping fallback (pure Python, no admin needed)
  3. MAC OUI lookup for vendor names
  4. TCP connect scan for open port detection on all devices
Populates the device DB with all live hosts on the local subnet.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import struct
import subprocess
import sys
import uuid
from datetime import datetime
from typing import Optional

from app.config import get_settings
from app.core.event_bus import publish
from app.core.logger import get_logger
from app.core.time_utils import local_now_iso
from app.database import crud
from app.database.session import AsyncSessionLocal

log = get_logger("network_scanner")
settings = get_settings()
_scan_running = False
_last_scan_started_at: Optional[str] = None
_last_scan_completed_at: Optional[str] = None
_last_scan_device_count = 0

# ── OUI → Vendor map (common prefixes) ─────────────────────────────────────────
_OUI_MAP: dict[str, str] = {
    "00:50:56": "VMware",        "00:0C:29": "VMware",
    "00:1A:11": "Google",        "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",  "E4:5F:01": "Raspberry Pi",
    "3C:22:FB": "Apple",         "A4:83:E7": "Apple",
    "F8:FF:C2": "Apple",         "00:11:22": "Cimsys",
    "FC:FB:FB": "Cisco",         "00:1B:54": "Cisco",
    "18:FE:34": "Espressif",     "60:01:94": "Espressif",
    "B4:E6:2D": "Espressif",     "A4:CF:12": "Espressif",
    "AC:67:B2": "Samsung",       "F4:7B:5E": "Samsung",
    "00:16:3E": "Xen",           "52:54:00": "QEMU/KVM",
    "00:1A:4B": "D-Link",        "1C:7E:E5": "D-Link",
    "00:26:5A": "TP-Link",       "A0:F3:C1": "TP-Link",
    "E8:DE:27": "TP-Link",       "C4:E9:84": "TP-Link",
    "34:60:F9": "TP-Link",       "98:DA:C4": "TP-Link",
    "00:1E:E5": "Netgear",       "C4:3D:C7": "Netgear",
    "B0:39:56": "OnePlus",       "10:CE:A9": "Xiaomi",
    "0C:1D:CF": "Xiaomi",        "F8:A4:5F": "Xiaomi",
    "B8:3E:59": "Lenovo",        "C8:3D:D4": "Lenovo",
    "00:23:AE": "Intel",         "8C:8D:28": "Intel",
    "F4:4D:30": "Intel",
}


def _vendor_from_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    prefix = mac.upper()[:8]
    return _OUI_MAP.get(prefix)


async def _ping_host(ip: str, timeout: float = 0.8) -> bool:
    """ICMP ping using OS ping command — works without admin."""
    try:
        param = "-n" if sys.platform == "win32" else "-c"
        proc = await asyncio.create_subprocess_exec(
            "ping", param, "1", "-w", "800" if sys.platform == "win32" else "1", ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=timeout + 0.5)
        return proc.returncode == 0
    except Exception:
        return False


def _arp_table() -> dict[str, str]:
    """Read the OS ARP cache — no admin needed."""
    result: dict[str, str] = {}
    try:
        output = subprocess.check_output(
            ["arp", "-a"], text=True, timeout=5,
            stderr=subprocess.DEVNULL
        )
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                ip_part = parts[0].strip("()")
                mac_part = parts[1]
                # normalise MAC separators
                mac = mac_part.replace("-", ":").lower()
                if len(mac) == 17 and mac not in ("ff:ff:ff:ff:ff:ff", "<incomplete>"):
                    try:
                        ipaddress.ip_address(ip_part)
                        result[ip_part] = mac
                    except ValueError:
                        pass
    except Exception as exc:
        log.debug("arp_table.failed", error=str(exc))
    return result


def _choose_scan_network() -> Optional[ipaddress.IPv4Network]:
    """Pick the subnet we should probe for device discovery."""
    candidates = [
        settings.scan_subnet.strip(),
        settings.server_display_ip.strip(),
        settings.gateway_ip.strip(),
    ]

    for candidate in candidates:
        if not candidate:
            continue
        try:
            if "/" in candidate:
                return ipaddress.ip_network(candidate, strict=False)
            ip = ipaddress.ip_address(candidate)
            if ip.is_loopback:
                continue
            return ipaddress.ip_network(f"{ip}/24", strict=False)
        except ValueError:
            continue

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        ip = ipaddress.ip_address(local_ip)
        if ip.is_loopback:
            return None
        return ipaddress.ip_network(f"{local_ip}/24", strict=False)
    except Exception as exc:
        log.warning("network_scanner.subnet_detect_failed", error=str(exc))
        return None


def _get_local_network() -> list[str]:
    """Detect the scan target subnet and expand it to host IPs."""
    network = _choose_scan_network()
    if not network:
        return []
    log.info("network_scanner.scan_target", subnet=str(network))
    return [str(host) for host in network.hosts()]


def get_effective_scan_subnet() -> Optional[str]:
    network = _choose_scan_network()
    return str(network) if network else None


def is_managed_asset_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if (
        parsed.is_multicast
        or parsed.is_unspecified
        or parsed.is_loopback
        or str(parsed).endswith(".255")
        or str(parsed).endswith(".0")
    ):
        return False

    network = _choose_scan_network()
    if network is not None:
        return parsed in network

    return parsed.is_private


async def _resolve_hostname(ip: str) -> Optional[str]:
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.getfqdn, ip)
        return result if result != ip else None
    except Exception:
        return None


# ── Common attack ports to scan on each discovered device ─────────────────────
_SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 5985, 6379,
    8080, 8443, 8888, 9200, 27017,
]

# Per-device open ports cache (ip → list of open ports)
_device_open_ports: dict[str, list[int]] = {}


async def _tcp_connect_scan(ip: str, port: int, timeout: float = 0.8) -> bool:
    """Fast TCP connect scan — returns True if port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def _scan_ports(ip: str, ports: list[int] | None = None) -> list[int]:
    """Scan a list of common ports on a single host. Returns list of open ports."""
    target_ports = ports or _SCAN_PORTS
    sem = asyncio.Semaphore(20)  # Limit concurrent connections per host

    async def _check(port: int) -> int | None:
        async with sem:
            is_open = await _tcp_connect_scan(ip, port)
            return port if is_open else None

    results = await asyncio.gather(*[_check(p) for p in target_ports])
    open_ports = [p for p in results if p is not None]
    _device_open_ports[ip] = open_ports
    return open_ports


def get_device_open_ports(ip: str) -> list[int]:
    """Return cached open ports for a device."""
    return _device_open_ports.get(ip, [])


def get_all_device_ports() -> dict[str, list[int]]:
    """Return all cached device port scan results."""
    return dict(_device_open_ports)


async def scan_network() -> list[dict]:
    """
    Full network scan:
     1. Ping entire /24 subnet concurrently
     2. Read ARP table for MACs
     3. Resolve hostnames
     4. Port-scan each live host for common attack ports
     5. Emit device_seen events for each live host
    Returns list of discovered device dicts.
    """
    global _scan_running, _last_scan_started_at, _last_scan_completed_at, _last_scan_device_count
    _scan_running = True
    _last_scan_started_at = local_now_iso()
    log.info("network_scanner.start")
    hosts = _get_local_network()
    if not hosts:
        log.warning("network_scanner.no_hosts_found")
        _last_scan_completed_at = local_now_iso()
        _last_scan_device_count = 0
        _scan_running = False
        return []

    # Concurrent pings (limit concurrency to avoid flooding)
    sem = asyncio.Semaphore(50)

    async def _ping_guarded(ip: str) -> Optional[str]:
        async with sem:
            alive = await _ping_host(ip)
            return ip if alive else None

    results = await asyncio.gather(*[_ping_guarded(h) for h in hosts])
    live_ips = [r for r in results if r is not None]

    # Filter out broadcast (.255), network (.0), and multicast addresses
    live_ips = [
        ip for ip in live_ips
        if not ip.endswith(".255") and not ip.endswith(".0")
        and not ip.startswith("224.") and not ip.startswith("239.")
    ]
    log.info("network_scanner.ping_done", alive=len(live_ips), total=len(hosts))

    # Read ARP cache for MACs (populated by pings)
    arp = _arp_table()

    # Port-scan all live hosts in parallel
    port_results = {}
    if live_ips:
        log.info("network_scanner.port_scan_start", hosts=len(live_ips), ports=len(_SCAN_PORTS))
        scan_tasks = {ip: asyncio.create_task(_scan_ports(ip)) for ip in live_ips}
        for ip, task in scan_tasks.items():
            try:
                port_results[ip] = await asyncio.wait_for(task, timeout=30)
            except asyncio.TimeoutError:
                port_results[ip] = []
        total_open = sum(len(v) for v in port_results.values())
        log.info("network_scanner.port_scan_done", total_open_ports=total_open)

    # Build device list
    devices = []
    async with AsyncSessionLocal() as db:
        for ip in live_ips:
            mac = arp.get(ip)
            hostname = await _resolve_hostname(ip)
            vendor = _vendor_from_mac(mac)
            open_ports = port_results.get(ip, [])
            device = {
                "src_ip": ip,
                "mac_address": mac,
                "hostname": hostname,
                "vendor": vendor,
                "open_ports": open_ports,
                "pkt_len": 0,
                "protocol": "arp_scan",
                "dst_port": None,
                "src_port": None,
                "flags": None,
                "is_syn": False,
                "is_ack": False,
                "is_rst": False,
                "timestamp": local_now_iso(),
            }
            devices.append(device)
            await crud.upsert_device_details(
                db,
                ip,
                mac_address=mac,
                hostname=hostname,
                vendor=vendor,
                open_ports=open_ports,
            )
            # Publish so the threat_agent / device registry processes it
            await publish("device_seen", device)

            # Log open ports for each device
            if open_ports:
                log.info("network_scanner.device_ports",
                         ip=ip, hostname=hostname, open_ports=open_ports)

        # ── Also register DHCP-leased devices (VMs that don't respond to ping) ──
        dhcp_ips = set()
        try:
            import os
            lease_file = "/var/lib/misc/dnsmasq.leases"
            if os.path.isfile(lease_file):
                with open(lease_file, "r") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            lease_mac = parts[1]
                            lease_ip = parts[2]
                            lease_hostname = parts[3] if parts[3] != "*" else None
                            # Only include IPs in our scan subnet
                            if is_managed_asset_ip(lease_ip) and lease_ip not in live_ips:
                                dhcp_ips.add(lease_ip)
                                await crud.upsert_device_details(
                                    db,
                                    lease_ip,
                                    mac_address=lease_mac,
                                    hostname=lease_hostname,
                                    vendor=_vendor_from_mac(lease_mac),
                                )
                                log.info("network_scanner.dhcp_lease_device",
                                         ip=lease_ip, hostname=lease_hostname, mac=lease_mac)
        except Exception as exc:
            log.warning("network_scanner.dhcp_lease_read_error", error=str(exc))

        subnet = get_effective_scan_subnet()
        if subnet:
            preserve_ips = {
                ip
                for ip in (settings.server_display_ip, settings.gateway_ip)
                if ip
            }
            # Include both ping-live and DHCP-leased IPs as "seen"
            all_live_ips = set(live_ips) | preserve_ips | dhcp_ips
            removed_stale = await crud.purge_unseen_devices_in_subnet(
                db,
                subnet,
                all_live_ips,
                preserve_ips=preserve_ips,
            )
            removed_invalid = await crud.purge_invalid_devices(db, subnet)
            if removed_stale or removed_invalid:
                log.info(
                    "network_scanner.removed_stale_devices",
                    stale=removed_stale,
                    invalid=removed_invalid,
                )
        await db.commit()

    _last_scan_completed_at = local_now_iso()
    _last_scan_device_count = len(devices)
    _scan_running = False
    log.info("network_scanner.done", devices=len(devices))
    return devices


def get_scan_state() -> dict[str, Optional[str] | int | bool]:
    return {
        "running": _scan_running,
        "started_at": _last_scan_started_at,
        "completed_at": _last_scan_completed_at,
        "device_count": _last_scan_device_count,
        "subnet": get_effective_scan_subnet(),
    }


# ── Real-time live device registry (in-memory, per IP) ─────────────────────────
_live_stats: dict[str, dict] = {}  # ip → live stats dict


def update_live_stats(features: dict) -> None:
    """Called per packet from packet_sniffer. Updates real-time stats."""
    ip = features.get("src_ip", "")
    if not ip:
        return
    now = local_now_iso()
    entry = _live_stats.setdefault(ip, {
        "ip": ip, "first_seen": now, "last_seen": now,
        "bytes_in": 0, "bytes_out": 0,
        "packets": 0, "syn_count": 0,
        "ports": set(), "protocols": set(),
    })
    entry["last_seen"] = now
    entry["packets"] += 1
    entry["bytes_in"] += features.get("pkt_len", 0)
    if features.get("is_syn"):
        entry["syn_count"] += 1
    proto = features.get("protocol")
    if proto:
        entry["protocols"].add(proto)
    port = features.get("dst_port")
    if port:
        entry["ports"].add(port)


def get_live_stats() -> list[dict]:
    """Return serialisable snapshot of all live device stats."""
    snapshot = []
    for ip, s in _live_stats.items():
        snapshot.append({
            "ip": ip,
            "first_seen": s["first_seen"],
            "last_seen": s["last_seen"],
            "bytes_in": s["bytes_in"],
            "packets": s["packets"],
            "syn_count": s["syn_count"],
            "unique_ports": len(s["ports"]),
            "protocols": list(s["protocols"]),
        })
    return snapshot


def get_live_stat(ip: str) -> dict:
    s = _live_stats.get(ip, {})
    if not s:
        return {}
    return {
        "ip": ip,
        "first_seen": s.get("first_seen"),
        "last_seen": s.get("last_seen"),
        "bytes_in": s.get("bytes_in", 0),
        "packets": s.get("packets", 0),
        "syn_count": s.get("syn_count", 0),
        "unique_ports": len(s.get("ports", set())),
        "protocols": list(s.get("protocols", set())),
    }
